# app/parsing/maillog_dovecot.py
from __future__ import annotations

import re
from typing import Optional, Tuple

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

# Syslog típico:
# Dec 21 00:00:30 svgs402 dovecot[2749896]: imap-login: Logged in: user=<x@d>, ... rip=1.2.3.4, ...
# Dec 21 00:03:35 svgs402 dovecot[2749896]: imap-login: Login aborted: ... (auth_failed): user=<x>, ... rip=1.2.3.4, ...
SYSLOG_RE = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+dovecot(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

# Login OK: imap-login / pop3-login
DOVECOT_LOGIN_OK_RE = re.compile(
    r"(?:imap|pop3)-login:\s+Logged in:\s+user=<(?P<user>[^>]+)>.*?\brip=(?P<ip>[0-9\.]+)",
    re.IGNORECASE,
)

# Auth failed real (tu ejemplo):
# imap-login: Login aborted: ... (auth_failed): user=<21ag024@institutoagora.edu.mx>, ... rip=129.222.64.52, ...
# Nota: el user a veces NO trae dominio (user=<investigaciones>)
DOVECOT_AUTH_FAIL_RE = re.compile(
    r"(?:imap|pop3)-login:.*?\(auth_failed\):\s*user=<(?P<user>[^>]+)>.*?\brip=(?P<ip>[0-9\.]+)",
    re.IGNORECASE,
)


def _split_addr(addr: str) -> Tuple[Optional[str], Optional[str]]:
    addr = (addr or "").strip().strip("<>").strip()
    if "@" in addr:
        u, d = addr.split("@", 1)
        return (u.strip() or None, d.strip().lower() or None)
    return (addr or None, None)


class MaillogDovecotParser(LogParser):
    source = "MAILLOG_DOVECOT"

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

        m = SYSLOG_RE.match(line)
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        msg = (m.group("msg") or "").strip()

        # 1) Login OK
        m_ok = DOVECOT_LOGIN_OK_RE.search(msg)
        if m_ok:
            user = (m_ok.group("user") or "").strip() or None
            ip = (m_ok.group("ip") or "").strip() or None
            _, dom = _split_addr(user or "")
            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="IMAP/POP3",
                ip_client=ip,
                domain=dom,
                username=user,
                message="DOVECOT LOGIN OK",
                extra={
                    "event_type": "auth_login",
                    "protocol": "imap_pop3",
                    "action": "success",
                    "auth_user": user,
                    "auth_success": True,
                },
                log_upload_id=log_upload_id,
            )

        # 2) Auth fail
        m_fail = DOVECOT_AUTH_FAIL_RE.search(msg)
        if m_fail:
            user = (m_fail.group("user") or "").strip() or None
            ip = (m_fail.group("ip") or "").strip() or None
            _, dom = _split_addr(user or "")
            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="IMAP/POP3",
                ip_client=ip,
                domain=dom,
                username=user,
                message="DOVECOT AUTH FAIL",
                extra={
                    "event_type": "auth_login",
                    "protocol": "imap_pop3",
                    "action": "fail",
                    "auth_user": user,
                    "auth_success": False,
                },
                log_upload_id=log_upload_id,
            )

        # 3) Ruido (disconnects, etc.)
        return None
