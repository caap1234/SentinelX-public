# app/parsing/nginx_access.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# Nginx combined típico:
# 1.2.3.4 - - [10/Dec/2025:14:23:00 -0600] "GET /index.php HTTP/1.1" 200 123 "-" "UA"
NGINX_REGEX = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
)


class NginxAccessParser(LogParser):
    source = "NGINX_ACCESS"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m = NGINX_REGEX.search(line or "")
        if not m:
            return None

        gd = m.groupdict()
        ts = parse_any_timestamp_to_utc(gd.get("time") or "")

        ip = (gd.get("ip") or "").strip() or None
        path = (gd.get("path") or "").strip() or "-"
        method = (gd.get("method") or "").strip() or "-"
        status = int(gd.get("status") or 0)

        raw_size = (gd.get("size") or "").strip()
        size = None if raw_size in ("", "-") else int(raw_size)

        ua = (gd.get("ua") or "").strip() or None
        ref = (gd.get("ref") or "").strip() or None

        extra = {
            "event_type": "http_access",
            "http": {
                "method": method,
                "path": path,
                "status": status,
                "bytes": size,
                "user_agent": ua,
                "referer": ref,
            },
        }

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="HTTP",
            ip_client=ip,
            message=f"{method} {path} {status}",
            extra=extra,
            log_upload_id=log_upload_id,
        )
