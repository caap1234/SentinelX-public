from __future__ import annotations

import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, unquote_plus, urlparse

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

APACHE_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/(?P<httpver>[\d.]+))?"\s+'
    r'(?P<status>\d{3})'
    r'(?:\s+(?P<size>\S+))?'
    r'.*$'
)

# Captura X-Forwarded-For del access_log de cPanel (viene al final entre comillas)
# ... "s" "X-Forwarded-For: 187.144.84.194" 2083
XFF_RE = re.compile(r'X-Forwarded-For:\s*(?P<ip>[0-9a-fA-F\.:]+)')

IP_LIKE_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")

# /cpsessXXXX/execute/Fileman/upload_files  (y variantes)
EXEC_FILEMAN_RE = re.compile(r"/execute/Fileman/(?P<func>[A-Za-z0-9_]+)", re.IGNORECASE)

# frontend filemanager url (solo para “área”)
FILEMAN_UI_HINT_RE = re.compile(r"/frontend/[^/]+/filemanager/", re.IGNORECASE)


def _safe_int(v: Optional[str]) -> Optional[int]:
    if not v or v == "-" or v.lower() == "null":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _norm_user(v: str) -> Optional[str]:
    if not v or v == "-" or v.lower() in ("(null)", "null"):
        return None
    return v


def _pick_best_client_ip(line: str, first_ip: str) -> Optional[str]:
    """
    En cPanel access_log, la IP inicial puede ser proxy/local.
    Preferimos X-Forwarded-For si está presente.
    """
    m = XFF_RE.search(line or "")
    if m:
        ip = (m.group("ip") or "").strip()
        if ip and IP_LIKE_RE.match(ip):
            # XFF puede traer lista "ip1, ip2"
            if "," in ip:
                ip = ip.split(",", 1)[0].strip()
            if ip and IP_LIKE_RE.match(ip):
                return ip
    # fallback a la primera IP
    if first_ip and IP_LIKE_RE.match(first_ip):
        return first_ip
    return None


def _qsv(qs: Dict[str, Any], key: str) -> Optional[str]:
    v = qs.get(key, [None])[0]
    if v is None:
        return None
    try:
        return unquote_plus(v)
    except Exception:
        return v


def _infer_area_action_and_filefunc(path: str, qs: Dict[str, Any]) -> tuple[str, str, Optional[str]]:
    """
    Decide:
    - area: panel | filemanager
    - action: view | api | login | file_action
    - file_func: upload_files | list_files | ... (cuando aplique)
    """
    p = (path or "").lower()

    # JSON API v2 (legacy) style params
    module = (_qsv(qs, "cpanel_jsonapi_module") or "").lower()
    func = (_qsv(qs, "cpanel_jsonapi_func") or "").lower()

    # Execute API (moderno)
    m_exec = EXEC_FILEMAN_RE.search(path or "")
    exec_file_func = (m_exec.group("func") or "").lower() if m_exec else None

    is_fileman = False
    if module == "fileman":
        is_fileman = True
    if exec_file_func:
        is_fileman = True
    if FILEMAN_UI_HINT_RE.search(path or ""):
        is_fileman = True
    if "/fileman" in p or "/filemanager" in p:
        is_fileman = True

    area = "filemanager" if is_fileman else "panel"

    # Login
    if "/login" in p or "login_only" in qs:
        return area, "login", None

    # API calls
    is_api = ("/json-api/" in p) or ("/execute/" in p) or ("cpanel_jsonapi" in (path or ""))
    if is_api:
        # Si es Fileman vía execute/Fileman/* o module=Fileman => file_action
        if area == "filemanager":
            file_action = exec_file_func or (func if func else None) or "api"
            return area, "file_action", file_action
        return area, "api", None

    # UI view
    if p:
        return area, "view", None

    return area, "unknown", None


def _infer_status_from_http(http_status: Optional[int], path: str, qs: Dict[str, Any]) -> Optional[str]:
    if http_status is None:
        return None
    if http_status in (401, 403):
        return "failed"
    if 200 <= http_status < 300:
        if "/login" in (path or "").lower() or "/json-api/" in (path or "").lower() or "/execute/" in (path or "").lower() or "login_only" in qs:
            return "ok"
    return None


class CPanelAccessParser(LogParser):
    source = "PANEL_ACCESS"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        line = (line or "").strip()
        if not line:
            return None

        m = APACHE_ACCESS_RE.match(line)
        if not m:
            return None

        first_ip = (m.group("ip") or "").strip()
        ip_client = _pick_best_client_ip(line, first_ip)
        if not ip_client:
            return None

        raw_user = m.group("user")
        user = _norm_user(raw_user)

        ts = parse_any_timestamp_to_utc(m.group("time") or "")

        method = m.group("method") or ""
        url_raw = m.group("url") or ""
        http_status = _safe_int(m.group("status"))
        size = _safe_int(m.group("size"))

        parsed = urlparse(url_raw)
        path = parsed.path or url_raw
        qs = parse_qs(parsed.query)

        cpanel_module = (_qsv(qs, "cpanel_jsonapi_module") or "").lower() or None
        cpanel_func = (_qsv(qs, "cpanel_jsonapi_func") or "").lower() or None

        area, action, file_func = _infer_area_action_and_filefunc(path, qs)
        status_text = _infer_status_from_http(http_status, path, qs)

        # extraer dir (muy útil para filemanager)
        dir_value = _qsv(qs, "dir")
        if dir_value:
            dir_value = dir_value.strip() or None

        msg_parts = [f"CPANEL {area.upper()}"]
        if action:
            msg_parts.append(action.upper())
        msg_parts.append(f"{method} {path}")
        if http_status is not None:
            msg_parts.append(f"HTTP {http_status}")
        if file_func:
            msg_parts.append(f"file_func={file_func}")
        if cpanel_module:
            msg_parts.append(f"module={cpanel_module}")
        if cpanel_func:
            msg_parts.append(f"func={cpanel_func}")
        msg = " · ".join(msg_parts)

        # event_type: panel_access por defecto, file_action si es filemanager con acción detectable
        event_type = "panel_access"
        if area == "filemanager" and action == "file_action":
            event_type = "file_action"

        extra: Dict[str, Any] = {
            "event_type": event_type,
            "panel": {
                "area": area,
                "action": action,
                "status": status_text,
                "http_method": method,
                "path": path,
                "url": url_raw,
                "status_code": http_status,
                "bytes": size,
                "cpanel_user": user,
                "cpanel_module": cpanel_module,
                "cpanel_func": cpanel_func,
                "query": {k: v[:3] for k, v in qs.items()} if qs else {},
            },
        }

        # Cuando es file_action, agrega bloque "file"
        if event_type == "file_action":
            extra["file"] = {
                "action": file_func,  # upload_files / list_files / ...
                "dir": dir_value,
            }

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="PANEL",
            ip_client=ip_client,
            username=user,
            message=msg,
            extra=extra,
            log_upload_id=log_upload_id,
        )
