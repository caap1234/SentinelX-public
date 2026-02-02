# app/parsing/panel_logs.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# 1.2.3.4 - user [10/12/2025:12:34:56 -0000] "... Login ok ..."
PANEL_LOGIN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\].*"(?:Login|login)\s+(?P<status>ok|failed).*"',
    re.IGNORECASE,
)


class PanelLogParser(LogParser):
    source = "PANEL_LOGIN"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = PANEL_LOGIN.search(line or "")
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        ip = m.group("ip")
        user = m.group("user")
        status = (m.group("status") or "").lower()

        action = "success" if status == "ok" else "fail"
        msg = "PANEL LOGIN OK" if action == "success" else "PANEL LOGIN FAIL"

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="PANEL",
            ip_client=ip,
            username=user,
            message=msg,
            extra={
                "event_type": "auth_login",
                "protocol": "cpanel",
                "action": action,
                "panel_user": user,
            },
            log_upload_id=log_upload_id,
        )
