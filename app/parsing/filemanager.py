# app/parsing/filemanager.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

FM_REGEX = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'user=(?P<user>\S+)\s+ip=(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'action=(?P<action>\S+)\s+path=(?P<path>\S+)'
    r'(?:\s+size=(?P<size>\d+))?'
    r'(?:\s+mode=(?P<mode>\d+))?'
)


class FileManagerParser(LogParser):
    source = "FILEMANAGER"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = FM_REGEX.search(line or "")
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        user = m.group("user")
        ip = m.group("ip")
        action = m.group("action")
        path = m.group("path")
        size = m.group("size")
        mode = m.group("mode")

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="SYSTEM",
            ip_client=ip,
            username=user,
            message=f"FILE {action} {path}",
            extra={
                "event_type": "file_action",
                "file": {
                    "action": action,
                    "path": path,
                    "size": int(size) if size else None,
                    "mode": mode,
                },
            },
            log_upload_id=log_upload_id,
        )
