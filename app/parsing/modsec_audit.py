# app/parsing/modsec_audit.py
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# -----------------------------------------------------------------------------
# 1) Formato "single-line" (error log style) - lo mantenemos
# -----------------------------------------------------------------------------
MODSEC_SINGLELINE_REGEX = re.compile(
    r'\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*'
    r'\[id "(?P<ruleid>[^"]+)"\].*'
    r'\[msg "(?P<msg>[^"]+)"\].*'
    r'\[hostname "(?P<host>[^"]+)"\].*'
    r'\[uri "(?P<uri>[^"]+)"\].*'
    r'\[client "(?P<ip>[^"]+)"\]'
)

# -----------------------------------------------------------------------------
# 2) Formato ModSecurity AUDIT LOG (multisección)
# Ejemplo:
# --26308a11-A--
# [26/Dec/2025:00:01:37.221839 --0600] <uniq> 181.46.9.65 ...
# --26308a11-B--
# GET http://... HTTP/1.1
# Host: ...
# --26308a11-F--
# HTTP/1.1 301 Moved Permanently
# -----------------------------------------------------------------------------
AUDIT_SECTION_MARKER = re.compile(r"^--(?P<txid>[0-9A-Za-z]+)-(?P<section>[A-Z])--\s*$")

AUDIT_A_LINE = re.compile(
    r"^\[(?P<time>[^\]]+)\]\s+(?P<uniq>\S+)\s+(?P<ip>\S+)\s+.*$"
)
AUDIT_REQUEST_LINE = re.compile(
    r"^(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(?P<url>\S+)\s+HTTP/\d(?:\.\d)?\s*$",
    re.IGNORECASE,
)
AUDIT_HOST_HEADER = re.compile(r"^Host:\s*(?P<host>\S+)\s*$", re.IGNORECASE)
AUDIT_STATUS_LINE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(?P<status>\d{3})\b.*$")


@dataclass
class _AuditState:
    txid: str
    section: Optional[str] = None

    # Capturas útiles
    ts_raw: Optional[str] = None
    ip_client: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    host: Optional[str] = None
    status_code: Optional[int] = None

    # Para debug/extra
    seen_sections: set[str] = field(default_factory=set)


class ModSecAuditParser(LogParser):
    source = "MODSEC"

    def __init__(self) -> None:
        # key: (server, log_upload_id, txid) para evitar choques entre uploads/servers
        self._sessions: Dict[tuple[str, Optional[int], str], _AuditState] = {}

    def _flush_event(
        self,
        state: _AuditState,
        server: str,
        *,
        log_upload_id: Optional[int],
    ) -> Optional[ParsedEvent]:
        # Requiere mínimo timestamp + ip (A) + algo del request (B)
        if not state.ts_raw or not state.ip_client:
            return None

        ts = parse_any_timestamp_to_utc(state.ts_raw)

        msg_parts = ["ModSec audit"]
        if state.status_code:
            msg_parts.append(f"HTTP {state.status_code}")
        if state.method and state.url:
            msg_parts.append(f"{state.method.upper()} {state.url}")
        elif state.url:
            msg_parts.append(state.url)

        message = " | ".join(msg_parts)

        extra = {
            "event_type": "waf_audit",
            "waf": {
                "engine": "modsecurity",
                "audit_txid": state.txid,
                "http": {
                    "method": state.method,
                    "url": state.url,
                    "status_code": state.status_code,
                    "host": state.host,
                },
                "seen_sections": sorted(list(state.seen_sections)),
            },
        }

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="HTTP",
            ip_client=state.ip_client,
            domain=state.host,
            message=message,
            extra=extra,
            log_upload_id=log_upload_id,
        )

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        raw = (line or "").rstrip("\n")

        # ---------------------------------------------------------------------
        # 1) Intento: formato single-line (tu parser original)
        # ---------------------------------------------------------------------
        m1 = MODSEC_SINGLELINE_REGEX.search(raw)
        if m1:
            ts = parse_any_timestamp_to_utc(m1.group("time") or "")
            ruleid = m1.group("ruleid")
            msg = m1.group("msg")
            host = m1.group("host")
            uri = m1.group("uri")
            ip = m1.group("ip")

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="HTTP",
                ip_client=ip,
                domain=host,
                message=f"ModSec {ruleid}: {msg}",
                extra={
                    "event_type": "waf_block",
                    "waf": {"engine": "modsecurity", "rule_id": ruleid, "uri": uri},
                },
                log_upload_id=log_upload_id,
            )

        # ---------------------------------------------------------------------
        # 2) Audit log: detectar marcador de sección
        # ---------------------------------------------------------------------
        mm = AUDIT_SECTION_MARKER.match(raw)
        if mm:
            txid = mm.group("txid")
            section = mm.group("section")

            key = (server, log_upload_id, txid)

            # Si llega un nuevo A y ya existía un estado previo con el mismo txid,
            # lo reseteamos (raro pero posible).
            if section == "A" and key in self._sessions:
                self._sessions.pop(key, None)

            # Si llega un A de un tx distinto, NO podemos saber aquí cuál fue el “anterior”
            # porque parse_line es line-by-line sin contexto de archivo; el flush correcto
            # se hará con Z/H del mismo txid. (Aun así, mucha gente corta por H/Z).

            state = self._sessions.get(key)
            if not state:
                state = _AuditState(txid=txid)
                self._sessions[key] = state

            state.section = section
            state.seen_sections.add(section)

            # Si es cierre, emitimos y limpiamos
            if section in ("Z", "H"):
                ev = self._flush_event(state, server, log_upload_id=log_upload_id)
                self._sessions.pop(key, None)
                return ev

            return None

        # ---------------------------------------------------------------------
        # 3) Audit log: consumir líneas según la sección actual
        # ---------------------------------------------------------------------
        # Buscamos el "último" state activo para este server/upload.
        # Como parse_line no trae txid por línea, usamos la última sesión que esté
        # "en curso" (heurística razonable si el audit log está en orden).
        active_key: Optional[tuple[str, Optional[int], str]] = None
        for k, st in reversed(list(self._sessions.items())):
            if k[0] == server and k[1] == log_upload_id and st.section:
                active_key = k
                break

        if not active_key:
            return None

        state = self._sessions[active_key]

        # Sección A: metadata (timestamp + ip)
        if state.section == "A":
            ma = AUDIT_A_LINE.match(raw)
            if ma:
                # parse_any_timestamp_to_utc suele aceptar "26/Dec/2025:00:01:37.221839 --0600"
                state.ts_raw = (ma.group("time") or "").strip()
                state.ip_client = (ma.group("ip") or "").strip()
            return None

        # Sección B: request + headers
        if state.section == "B":
            mr = AUDIT_REQUEST_LINE.match(raw)
            if mr:
                state.method = (mr.group("method") or "").upper()
                state.url = (mr.group("url") or "").strip()
                return None

            mh = AUDIT_HOST_HEADER.match(raw)
            if mh:
                state.host = (mh.group("host") or "").strip()
                return None

            return None

        # Sección F: response status
        if state.section == "F":
            ms = AUDIT_STATUS_LINE.match(raw)
            if ms:
                try:
                    state.status_code = int(ms.group("status"))
                except Exception:
                    state.status_code = None
            return None

        return None
