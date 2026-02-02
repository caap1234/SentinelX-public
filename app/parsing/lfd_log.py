# app/parsing/lfd_log.py
from __future__ import annotations

import re
from typing import Optional, List, Dict, Any

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# Ejemplos soportados:
# Jan 23 14:11:26 host lfd[3582766]: SMTP Brute Force attack v4 189.154.129.15 - ignored
# Jan 23 14:15:15 host lfd[74875]: (Block-http-requests-xmlrpc-error-log) ... with IP: 206.84.236.205 (...) - *Blocked in csf* for 604800 secs [LF_CUSTOMTRIGGER]
# Jan 23 13:50:45 host lfd[47367]: (XMLRPC-Attack) Attack over xmlrpc.php from 20.92.72.15 (...) - *Blocked in csf* for 604800 secs [LF_CUSTOMTRIGGER]
# Jan 23 08:51:11 host lfd[3904246]: (CT) IP 198.100.147.132 (...) found to have 54 connections - *Blocked in csf* for 1200 secs [CT_LIMIT]

LFD_LINE_REGEX = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+lfd\[\d+\]:\s+'
    r'(?:(?P<trigger>\([^)]+\))\s+)?'
    r'(?P<msg>.*)$'
)

# IP patterns
IP_REGEX = re.compile(
    r'\b(?:from|with\s+IP:|IP)\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\b',
    re.IGNORECASE,
)
# "v4 1.2.3.4" / "v1 1.2.3.4"
VNUM_IP_REGEX = re.compile(r'\bv\d+\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\b', re.IGNORECASE)
# "... bots 1.2.3.4 - ignored"
TRAILING_IP_IGNORED_REGEX = re.compile(
    r'\b(?P<ip>\d+\.\d+\.\d+\.\d+)\b(?=.*\b-?\s*ignored\b)',
    re.IGNORECASE,
)

# "5 in the last 3600 secs"
COUNT_WINDOW_REGEX = re.compile(
    r':\s*(?P<count>\d+)\s+in\s+the\s+last\s+(?P<window>\d+)\s+secs\b',
    re.IGNORECASE,
)

# "*Blocked in csf* for 604800 secs" (o "... blocked ... for 1200 secs")
BLOCK_FOR_REGEX = re.compile(r'\bfor\s+(?P<secs>\d+)\s+secs\b', re.IGNORECASE)

# "port=443" (puede repetirse)
PORT_KV_REGEX = re.compile(r'\bport=(?P<port>\d+)\b', re.IGNORECASE)
# "ports: 80,443" (por si aparece en algún custom trigger)
PORTS_LIST_REGEX = re.compile(r'\bports?\s*[:=]\s*(?P<ports>[\d,\s]+)\b', re.IGNORECASE)

# Tag final [LF_CUSTOMTRIGGER], [CT_LIMIT], etc.
TAG_REGEX = re.compile(r'\[(?P<tag>[A-Z0-9_]+)\]\s*$', re.IGNORECASE)

BLOCK_HINT = re.compile(r"\*blocked\b|\bblocked\b|\bcsf\b", re.IGNORECASE)
CSF_HINT = re.compile(r"\bcsf\b", re.IGNORECASE)
IGNORED_HINT = re.compile(r"\bignored\b", re.IGNORECASE)


def _extract_ip(msg: str) -> Optional[str]:
    for rx in (IP_REGEX, VNUM_IP_REGEX, TRAILING_IP_IGNORED_REGEX):
        m = rx.search(msg or "")
        if m:
            return m.group("ip")
    return None


def _extract_ports(msg: str) -> List[int]:
    ports: List[int] = []

    for m in PORT_KV_REGEX.finditer(msg or ""):
        try:
            ports.append(int(m.group("port")))
        except Exception:
            pass

    m2 = PORTS_LIST_REGEX.search(msg or "")
    if m2:
        raw = m2.group("ports") or ""
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports.append(int(part))
            except Exception:
                continue

    # uniq manteniendo orden
    seen = set()
    out: List[int] = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _extract_reason(msg: str, trigger: str) -> str:
    """
    reason = token estable para reglas/dashboards.
    - Si existe trigger (..), lo usamos como base pero normalizado (snake-ish).
    - Si no, heurística por keywords del mensaje.
    """
    t = (trigger or "").strip()
    if t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()

    if t:
        # Normalización suave: lower + espacios/guiones -> underscore + limpia chars raros
        base = re.sub(r"[\s\-]+", "_", t.lower())
        base = re.sub(r"[^a-z0-9_\.]+", "", base)
        return base or "lfd_event"

    low = (msg or "").lower()
    if "smtp brute force" in low:
        return "smtp_bruteforce"
    if "failed smtp auth" in low:
        return "smtp_auth_failed"
    if "smtp invalid helo" in low or "invalid helo" in low:
        return "smtp_invalid_helo"
    if "no such user" in low:
        return "smtp_no_such_user"
    if "xmlrpc" in low:
        return "xmlrpc_activity"
    if "wlwmanifest.xml" in low:
        return "wlwmanifest_activity"
    if "python-requests" in low:
        return "python_requests_activity"
    if "crawler" in low or "spider" in low:
        return "crawler_bot"
    if "robots.txt" in low:
        return "robots_txt_activity"
    if "add-to-cart" in low:
        return "add_to_cart_activity"
    if "connection" in low and ("limit" in low or "found to have" in low):
        return "connection_limit"
    return "lfd_event"


def _infer_service(msg: str, trigger: str) -> str:
    """
    service alto nivel para UI/filtros.
    """
    low = (msg or "").lower()
    trig = (trigger or "").lower()

    if "ssh" in trig or "sshd" in low:
        return "SSH"
    if "smtp" in low or "helo" in low or "mail" in low:
        return "SMTP"
    if "xmlrpc" in low or "http" in low or "robots.txt" in low or "wlwmanifest" in low or "add-to-cart" in low:
        return "HTTP"
    return "SYSTEM"


class LfdLogParser(LogParser):
    source = "LFD"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = LFD_LINE_REGEX.search(line or "")
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("ts") or "")
        msg = (m.group("msg") or "").strip()

        ip = _extract_ip(msg)
        # Si algún día quieres conservar eventos sin IP, aquí sería el switch.
        if not ip:
            return None

        trigger_raw = (m.group("trigger") or "").strip()
        trigger = trigger_raw[1:-1].strip() if (trigger_raw.startswith("(") and trigger_raw.endswith(")")) else ""

        # action
        action = "info"
        if BLOCK_HINT.search(msg):
            action = "blocked"
        elif IGNORED_HINT.search(msg):
            action = "ignored"

        # ports
        ports = _extract_ports(msg)

        # count + window
        count = window_secs = None
        mcw = COUNT_WINDOW_REGEX.search(msg)
        if mcw:
            try:
                count = int(mcw.group("count"))
                window_secs = int(mcw.group("window"))
            except Exception:
                pass

        # block seconds (solo si es blocked)
        block_seconds = None
        if action == "blocked":
            mb = BLOCK_FOR_REGEX.search(msg)
            if mb:
                try:
                    block_seconds = int(mb.group("secs"))
                except Exception:
                    pass

        # tag final [XXX]
        lfd_tag = None
        mt = TAG_REGEX.search(msg)
        if mt:
            lfd_tag = (mt.group("tag") or "").upper()

        reason = _extract_reason(msg, trigger)
        service = _infer_service(msg, trigger)

        extra: Dict[str, Any] = {
            "event_type": "security_signal",
            "kind": "lfd",
            "action": action,                 # blocked | ignored | info
            "reason": reason,                 # token estable para reglas
            "lfd_trigger": trigger or None,   # trigger humano original (si existe)
            "lfd_tag": lfd_tag,               # [LF_CUSTOMTRIGGER], [CT_LIMIT], etc.
            "ports": ports,                   # lista
            "port": ports[0] if ports else None,  # compat rápida
            "count": count,
            "window_secs": window_secs,
            "block_seconds": block_seconds,
            "blocked_tool": "csf" if CSF_HINT.search(msg) else None,
        }

        # limpia None/[] para ahorrar espacio
        extra = {k: v for k, v in extra.items() if v is not None and v != []}

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service=service,
            ip_client=ip,
            message=msg,
            extra=extra,
            log_upload_id=log_upload_id,
        )

