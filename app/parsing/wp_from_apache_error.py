# app/parsing/wp_from_apache_error.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.types import ParsedEvent

APACHE_ERR_REGEX = re.compile(r"^\[(?P<time>[^\]]+)\]\s*(?P<rest>.*)$")

PHP_MSG_REGEX = re.compile(
    r"PHP\s+(?P<level>Warning|Fatal error|Parse error|Notice):\s+(?P<msg>.+)",
    re.IGNORECASE,
)

WP_HINT_REGEX = re.compile(
    r"(wp-content|wp-includes|/wp-admin/|wp-[\w-]+\.php|class-wp[\w-]*\.php)",
    re.IGNORECASE,
)

STRONG_SIGNAL_REGEX = re.compile(
    r"(failed opening required|no such file or directory|require_once|require\(|include_once|include\()",
    re.IGNORECASE,
)

CORE_FILE_REGEX = re.compile(r"(wp-[\w-]+\.php|class-wp[\w-]*\.php)", re.IGNORECASE)
MISSING_FILE_REGEX = re.compile(r"Failed opening required '([^']+)'", re.IGNORECASE)
MEMORY_EXHAUSTED_REGEX = re.compile(r"Allowed memory size of \d+ bytes exhausted", re.IGNORECASE)

APACHE_CLIENT_IP_REGEX = re.compile(r"\[client\s+([0-9a-fA-F\.:]+)")
AUTO_INDEX_HINTS = ("AH01276", "autoindex:error")


def detect_wp_from_apache_error_line(
    *,
    line: str,
    server: str,
    log_upload_id: Optional[int] = None,
) -> Optional[ParsedEvent]:
    m = APACHE_ERR_REGEX.match(line or "")
    if not m:
        return None

    ts_raw = m.group("time") or ""
    rest = (m.group("rest") or "").strip()
    lower_rest = rest.lower()

    if any(h.lower() in lower_rest for h in AUTO_INDEX_HINTS):
        return None

    ip_client: Optional[str] = None
    m_client = APACHE_CLIENT_IP_REGEX.search(rest)
    if m_client:
        ip_client = m_client.group(1).split(":", 1)[0]

    m_php = PHP_MSG_REGEX.search(rest)
    if not m_php:
        return None

    level = (m_php.group("level") or "").strip()
    msg = (m_php.group("msg") or "").strip()

    # “huele a WP”
    if not WP_HINT_REGEX.search(msg):
        return None

    is_memory = bool(MEMORY_EXHAUSTED_REGEX.search(msg))
    is_strong = bool(STRONG_SIGNAL_REGEX.search(msg))
    if not is_memory and not is_strong:
        return None

    ts = parse_any_timestamp_to_utc(ts_raw)

    core_file: Optional[str] = None
    missing_file: Optional[str] = None

    m_core = CORE_FILE_REGEX.search(msg)
    if m_core:
        core_file = m_core.group(1)

    m_missing = MISSING_FILE_REGEX.search(msg)
    if m_missing:
        missing_file = m_missing.group(1)

    extra = {
        "event_type": "app_error",
        "app": "wordpress",
        "level": level,
        "wp": {
            "kind": "php_error",
        },
    }

    if is_memory:
        extra["wp"]["kind"] = "memory_exhausted"
        extra["noise"] = True

    if missing_file or core_file:
        extra["wp"]["kind"] = "missing_file"

    if core_file:
        extra["wp"]["core_file"] = core_file
    if missing_file:
        extra["wp"]["missing_file"] = missing_file

    return ParsedEvent(
        timestamp_utc=ts,
        server=server,
        source="APACHE_ERROR",
        service="WORDPRESS",
        ip_client=ip_client,
        message=msg,
        extra=extra,
        log_upload_id=log_upload_id,
    )
