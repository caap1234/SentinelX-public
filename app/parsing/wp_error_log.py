# app/parsing/wp_error_log.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

WP_ERROR_REGEX = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+PHP\s+"
    r"(?P<level>Warning|Fatal error|Parse error|Notice):\s+"
    r"(?P<msg>.+)",
    re.IGNORECASE,
)

WP_HINT_REGEX = re.compile(r"(wp-content|wp-includes|/wp-admin/|wp-[\w-]+\.php)", re.IGNORECASE)
CORE_FILE_REGEX = re.compile(r"(wp-[\w-]+\.php|class-wp[\w-]*\.php)", re.IGNORECASE)
MISSING_FILE_REGEX = re.compile(r"Failed opening required '([^']+)'", re.IGNORECASE)
MEMORY_EXHAUSTED_REGEX = re.compile(r"Allowed memory size of \d+ bytes exhausted", re.IGNORECASE)


class WpErrorLogParser(LogParser):
    source = "WP_ERROR"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = WP_ERROR_REGEX.search(line or "")
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        level = (m.group("level") or "").strip()
        msg = (m.group("msg") or "").strip()

        core_file = None
        missing_file = None

        mc = CORE_FILE_REGEX.search(msg)
        if mc:
            core_file = mc.group(1)

        mm = MISSING_FILE_REGEX.search(msg)
        if mm:
            missing_file = mm.group(1)

        wp_hint = bool(WP_HINT_REGEX.search(msg))
        missing_hint = bool(missing_file and WP_HINT_REGEX.search(missing_file))
        core_hint = bool(core_file and WP_HINT_REGEX.search(core_file))
        if not (wp_hint or missing_hint or core_hint):
            return None

        wp_kind = "php_error"
        if MEMORY_EXHAUSTED_REGEX.search(msg):
            wp_kind = "memory_exhausted"
        elif missing_file or core_file:
            wp_kind = "missing_file"

        signature = msg
        signature = re.sub(r"/home/\S+", "/home/<redacted>", signature)
        signature = re.sub(r"\b\d+\b", "<n>", signature)
        signature = signature[:300]

        extra = {
            "event_type": "app_error",
            "app": "wordpress",
            "level": level,
            "signature": signature,
            "wp": {"kind": wp_kind},
        }
        if core_file:
            extra["wp"]["core_file"] = core_file
        if missing_file:
            extra["wp"]["missing_file"] = missing_file
        if wp_kind == "memory_exhausted":
            extra["noise"] = True

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="WORDPRESS",
            message=msg,
            extra=extra,
            log_upload_id=log_upload_id,
        )
