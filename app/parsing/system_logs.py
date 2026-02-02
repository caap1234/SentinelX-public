# app/parsing/system_logs.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# Dec 10 12:34:56 server kernel: msg...
SYSLOG_REGEX = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)'
)

IMUNIFY_DEBUG_PREFIX = "auth-worker: debug: imunify360:"


class SystemLogParser(LogParser):
    source = "SYSTEM"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = SYSLOG_REGEX.search(line or "")
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("ts") or "")
        proc = (m.group("proc") or "").lower()
        msg = (m.group("msg") or "").strip()

        service = "SYSTEM"
        if "httpd" in proc or "apache" in proc:
            service = "HTTP"
        elif "exim" in proc:
            service = "SMTP"
        elif "sshd" in proc:
            service = "SSH"

        msg_l = msg.lower()
        is_imunify_debug = msg_l.startswith(IMUNIFY_DEBUG_PREFIX)

        extra = {
            "event_type": "system_log",
            "process": proc,
        }

        # ✅ Marcar ruido (pero conservarlo)
        if is_imunify_debug:
            extra.update(
                {
                    "noise": True,
                    "kind": "imunify_debug",
                }
            )

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service=service,
            message=msg,
            extra=extra,
            log_upload_id=log_upload_id,
        )
