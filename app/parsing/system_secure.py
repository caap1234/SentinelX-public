# app/parsing/system_secure.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

SSH_FAIL = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: '
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
)

SSH_OK = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: '
    r'Accepted (?P<auth_method>\S+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)'
)


class SecureLogParser(LogParser):
    source = "SSH_SECURE"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        m_fail = SSH_FAIL.search(line or "")
        if m_fail:
            ts = parse_any_timestamp_to_utc(m_fail.group("ts") or "")
            user = m_fail.group("user")
            ip = m_fail.group("ip")
            port = int(m_fail.group("port"))

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SSH",
                ip_client=ip,
                username=user,
                message="SSH AUTH FAIL",
                extra={
                    "event_type": "auth_login",
                    "action": "fail",
                    "protocol": "ssh",
                    "port": port,
                    "auth_success": False,
                },
                log_upload_id=log_upload_id,
            )

        m_ok = SSH_OK.search(line or "")
        if m_ok:
            ts = parse_any_timestamp_to_utc(m_ok.group("ts") or "")
            user = m_ok.group("user")
            ip = m_ok.group("ip")
            port = int(m_ok.group("port"))
            auth_method = m_ok.group("auth_method")

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SSH",
                ip_client=ip,
                username=user,
                message="SSH AUTH OK",
                extra={
                    "event_type": "auth_login",
                    "action": "success",
                    "protocol": "ssh",
                    "port": port,
                    "auth_method": auth_method,
                    "auth_success": True,
                },
                log_upload_id=log_upload_id,
            )

        return None
