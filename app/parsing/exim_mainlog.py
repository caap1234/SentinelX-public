# app/parsing/exim_mainlog.py
from __future__ import annotations

import re
from typing import Optional, Tuple

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent


# AUTH fail: SMTP AUTH attempt rejected (submission)
EXIM_AUTH_FAIL = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*authenticator failed.*\[(?P<ip>\d+\.\d+\.\d+\.\d+)\]: (?P<msg>.*)",
    re.IGNORECASE,
)

# AUTH ok: authenticated submission. Must be "<=" and include A= or authenticated_id=
EXIM_AUTH_SUBMISSION_OK = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"<=\s+(?P<from>\S+)\s+.*"
    r".*?(?:\sA=|\sauthenticated_id=)(?P<user>[^\s]+).*"
    r"\sH=[^\s]+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\](?::\d+)?",
    re.IGNORECASE,
)

# Inbound (remote or local) message accepted. Support [IP] and [IP]:PORT
EXIM_INBOUND = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"<=\s+(?P<from>\S+)\s+.*?"
    r"(?:\sH=[^\s]+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\](?::\d+)?)?"
    r".*?(?:\sP=(?P<proto>[^\s]+))?",
    re.IGNORECASE,
)

# Inbound with subject + rcpt (typical Exim line includes: T="..." for rcpt@dom)
EXIM_INBOUND_SUBJECT = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*'
    r'<=\s+(?P<from>\S+)\s+.*?'
    r'(?:\sH=[^\s]+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\](?::\d+)?)?'
    r'.*?(?:\sP=(?P<proto>[^\s]+))?'
    r'.*?\sT="(?P<subject>[^"]+)"\s+for\s+(?P<rcpt>\S+)',
    re.IGNORECASE,
)

# Outbound delivery attempt, capturing optional response code from C="250 ..."
EXIM_OUTBOUND = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*"
    r"(?:=>|->)\s+(?P<to>.+?)\s+"
    r".*?(?:H=[^\s]+\s+\[(?P<ip>\d+\.\d+\.\d+\.\d+)\](?::\d+)?)?"
    r".*?(?:\sC=\"(?P<code>\d{3})\b[^\"]*\")?",
    re.IGNORECASE,
)

# Hard fail delivery line: starts with "**"
EXIM_OUTBOUND_FAIL = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<msgid>\S+)\s+\*\*\s+(?P<rcpt>\S+)\s+.*?:\s+(?P<reason>.+)$",
    re.IGNORECASE,
)

EXIM_INVALID_DOMAIN = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*(Unrouteable address|Host or domain name not found).*<(?P<rcpt>[^>]+)>",
    re.IGNORECASE,
)

EXIM_RETRY = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*retry time not reached for any host",
    re.IGNORECASE,
)

# Rate-limit / policy enforcement (your examples)
EXIM_ENFORCE_LIMIT = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<msgid>\S+)\s+\*\*\s+(?P<rcpt>\S+)\s+R=enforce_mail_permissions\s*:\s*"
    r"Domain\s+(?P<domain>[A-Za-z0-9\.\-]+)\s+has\s+exceeded\s+(?P<detail>.+?)\s+allowed\.\s+Message\s+discarded\.",
    re.IGNORECASE,
)

_AUTH_MARKERS = (" authenticated_id=", " A=")


def _split_addr(addr: str) -> Tuple[Optional[str], Optional[str]]:
    addr = (addr or "").strip().strip("<>").strip()
    if "@" in addr:
        u, d = addr.split("@", 1)
        return (u.strip() or None, d.strip().lower() or None)
    return (addr or None, None)


def _delivery_action_from_code(code: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (action, kind):
      - 2xx => ("success", None)
      - 4xx => ("defer", "temporary_failure")
      - 5xx => ("fail", "permanent_failure")
      - None => (None, None)
    """
    if not code:
        return (None, None)
    try:
        c = int(code)
    except Exception:
        return (None, None)

    if 200 <= c <= 299:
        return ("success", None)
    if 400 <= c <= 499:
        return ("defer", "temporary_failure")
    if 500 <= c <= 599:
        return ("fail", "permanent_failure")
    return (None, None)


class EximMainlogParser(LogParser):
    source = "EXIM_MAINLOG"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        line = line or ""

        # AUTH FAIL (submission)
        m_fail = EXIM_AUTH_FAIL.search(line)
        if m_fail:
            ts = parse_any_timestamp_to_utc(m_fail.group("time") or "")
            ip = (m_fail.group("ip") or "").strip() or None
            msg = (m_fail.group("msg") or "").strip()
            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                ip_client=ip,
                message=f"SMTP AUTH FAIL: {msg}",
                extra={
                    "event_type": "auth_login",
                    "protocol": "smtp",
                    "action": "fail",
                    "direction": "outbound",
                    "auth_success": False,
                },
                log_upload_id=log_upload_id,
            )

        # AUTH OK (submission) - only authenticated users
        m_ok = EXIM_AUTH_SUBMISSION_OK.search(line)
        if m_ok:
            ts = parse_any_timestamp_to_utc(m_ok.group("time") or "")
            ip = (m_ok.group("ip") or "").strip() or None

            user = (m_ok.group("user") or "").strip() or None
            _, dom = _split_addr(user or "")

            from_addr = (m_ok.group("from") or "").strip() or None
            _, from_domain = _split_addr(from_addr or "")

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                ip_client=ip,
                domain=dom or from_domain,
                username=user,
                message="SMTP AUTH OK (submission)",
                extra={
                    "event_type": "auth_login",
                    "protocol": "smtp",
                    "action": "success",
                    "direction": "outbound",
                    "auth_user": user,
                    "mail_from": from_addr,
                    "auth_success": True,
                },
                log_upload_id=log_upload_id,
            )

        # Policy/rate-limit enforcement (discarded)
        m_lim = EXIM_ENFORCE_LIMIT.search(line)
        if m_lim:
            ts = parse_any_timestamp_to_utc(m_lim.group("time") or "")
            rcpt = (m_lim.group("rcpt") or "").strip()
            domain = (m_lim.group("domain") or "").strip().lower() or None
            detail = (m_lim.group("detail") or "").strip()

            # Derive recipient domain too (useful for correlations)
            _, rcpt_dom = _split_addr(rcpt)

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                domain=domain or rcpt_dom,
                message="SMTP OUTBOUND RATE LIMIT (discarded)",
                extra={
                    "event_type": "mail_flow",
                    "direction": "outbound",
                    "action": "fail",
                    "kind": "rate_limit",
                    "recipient": rcpt,
                    "policy_domain": domain,
                    "detail": detail,
                },
                log_upload_id=log_upload_id,
            )

        # Outbound hard fail lines ( "** rcpt ... : reason" )
        m_of = EXIM_OUTBOUND_FAIL.search(line)
        if m_of:
            ts = parse_any_timestamp_to_utc(m_of.group("time") or "")
            rcpt = (m_of.group("rcpt") or "").strip()
            reason = (m_of.group("reason") or "").strip()
            _, dom = _split_addr(rcpt)

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                domain=dom,
                message="SMTP OUTBOUND FAIL",
                extra={
                    "event_type": "mail_flow",
                    "direction": "outbound",
                    "action": "fail",
                    "kind": "delivery_failure",
                    "recipient": rcpt,
                    "reason": reason,
                },
                log_upload_id=log_upload_id,
            )

        # Inbound mail flow (includes local generated messages too)
        # Note: submissions with auth markers are handled above.
        if any(m in line for m in _AUTH_MARKERS):
            return None

        # Inbound with subject (if present)
        m_in_subj = EXIM_INBOUND_SUBJECT.search(line)
        if m_in_subj:
            ts = parse_any_timestamp_to_utc(m_in_subj.group("time") or "")
            ip = (m_in_subj.group("ip") or "").strip() or None
            from_addr = (m_in_subj.group("from") or "").strip() or None
            rcpt = (m_in_subj.group("rcpt") or "").strip() or None
            subject = (m_in_subj.group("subject") or "").strip() or None
            proto = (m_in_subj.group("proto") or "").strip().lower() or None

            _, from_domain = _split_addr(from_addr or "")
            _, rcpt_domain = _split_addr(rcpt or "")

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                ip_client=ip,
                domain=rcpt_domain or from_domain,
                message="SMTP INBOUND",
                extra={
                    "event_type": "mail_flow",
                    "direction": "inbound",
                    "from": from_addr,
                    "to": rcpt,
                    "proto": proto,
                    "subject": subject,
                    "auth_success": False,
                },
                log_upload_id=log_upload_id,
            )

        # Fallback inbound without subject
        m_in = EXIM_INBOUND.search(line)
        if m_in:
            ts = parse_any_timestamp_to_utc(m_in.group("time") or "")
            ip = (m_in.group("ip") or "").strip() or None
            from_addr = (m_in.group("from") or "").strip() or None
            _, from_domain = _split_addr(from_addr or "")
            proto = (m_in.group("proto") or "").strip().lower() or None

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                ip_client=ip,
                domain=from_domain,
                message="SMTP INBOUND",
                extra={
                    "event_type": "mail_flow",
                    "direction": "inbound",
                    "from": from_addr,
                    "proto": proto,
                    "auth_success": False,
                },
                log_upload_id=log_upload_id,
            )

        # Outbound delivery attempt (success/defer/fail if we have C="### ...")
        m_out = EXIM_OUTBOUND.search(line)
        if m_out:
            ts = parse_any_timestamp_to_utc(m_out.group("time") or "")
            ip = (m_out.group("ip") or "").strip() or None
            code = (m_out.group("code") or "").strip() or None
            action, kind = _delivery_action_from_code(code)

            to_raw = (m_out.group("to") or "").strip() or None
            to_addr = to_raw
            # Try to find <addr@dom> inside
            if to_raw and "<" in to_raw and ">" in to_raw:
                inside = to_raw.split("<", 1)[1].split(">", 1)[0].strip()
                if inside:
                    to_addr = inside

            _, to_domain = _split_addr(to_addr or "")

            extra = {
                "event_type": "mail_flow",
                "direction": "outbound",
                "to": to_addr,
                "auth_success": False,
            }
            if code:
                extra["smtp_reply_code"] = int(code) if code.isdigit() else code
            if action:
                extra["action"] = action  # success | defer | fail
            if kind:
                extra["kind"] = kind

            # Mensaje más claro según acción
            if action == "success":
                msg = "SMTP OUTBOUND DELIVERED"
            elif action == "defer":
                msg = "SMTP OUTBOUND DEFERRED"
            elif action == "fail":
                msg = "SMTP OUTBOUND FAILED"
            else:
                msg = "SMTP OUTBOUND"

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                ip_client=ip,
                domain=to_domain,
                message=msg,
                extra=extra,
                log_upload_id=log_upload_id,
            )

        m_inv = EXIM_INVALID_DOMAIN.search(line)
        if m_inv:
            ts = parse_any_timestamp_to_utc(m_inv.group("time") or "")
            rcpt = (m_inv.group("rcpt") or "").strip()
            _, dom = _split_addr(rcpt)
            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                domain=dom,
                message=f"INVALID DOMAIN for {rcpt}",
                extra={
                    "event_type": "mail_flow",
                    "direction": "outbound",
                    "action": "fail",
                    "kind": "invalid_domain",
                    "recipient": rcpt,
                },
                log_upload_id=log_upload_id,
            )

        m_retry = EXIM_RETRY.search(line)
        if m_retry:
            ts = parse_any_timestamp_to_utc(m_retry.group("time") or "")
            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="SMTP",
                message="SMTP RETRY",
                extra={
                    "event_type": "mail_flow",
                    "direction": "outbound",
                    "kind": "retry",
                },
                log_upload_id=log_upload_id,
            )

        return None
