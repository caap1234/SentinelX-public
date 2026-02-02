# app/parsing/apache_error_log.py
from __future__ import annotations

import re
from typing import Optional

from app.core.timeutils import parse_any_timestamp_to_utc
from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent
from app.parsing.wp_from_apache_error import detect_wp_from_apache_error_line

APACHE_ERR_GENERIC_REGEX = re.compile(r"^\[(?P<time>[^\]]+)\]\s*(?P<rest>.*)$")
APACHE_CLIENT_IP_REGEX = re.compile(r"\[client\s+([0-9a-fA-F\.:]+)")
AUTO_INDEX_HINTS = ("AH01276", "autoindex:error")

# referer: http(s)://host/...
APACHE_REFERER_HOST_REGEX = re.compile(r"referer:\s*https?://([^/\s]+)", re.IGNORECASE)


class ApacheErrorLogParser(LogParser):
    source = "APACHE_ERROR"

    def parse_line(
        self,
        line: str,
        server: str,
        *,
        log_upload_id: Optional[int] = None,
    ) -> Optional[ParsedEvent]:
        line = (line or "").rstrip("\n")
        if not line:
            return None

        m = APACHE_ERR_GENERIC_REGEX.match(line)
        if not m:
            return None

        ts = parse_any_timestamp_to_utc(m.group("time") or "")
        rest = (m.group("rest") or "").strip()

        # ip_client si viene en [client X]
        ip_client: Optional[str] = None
        m_ip = APACHE_CLIENT_IP_REGEX.search(rest)
        if m_ip:
            # si viniera IPv6 con puerto o similares, nos quedamos con lo de antes del primer ":"
            ip_client = m_ip.group(1).split(":", 1)[0]

        lower = rest.lower()

        # host a partir del referer si existe
        referer_host: Optional[str] = None
        m_ref = APACHE_REFERER_HOST_REGEX.search(rest)
        if m_ref:
            referer_host = (m_ref.group(1) or "").strip().lower() or None

        # Ruido común (autoindex)
        if any(h.lower() in lower for h in AUTO_INDEX_HINTS):
            extra = {
                "event_type": "http_error",
                "kind": "autoindex_forbidden",
                "noise": True,
            }
            if referer_host:
                extra["referer_host"] = referer_host

            return ParsedEvent(
                timestamp_utc=ts,
                server=server,
                source=self.source,
                service="HTTP",
                ip_client=ip_client,
                message="AUTOINDEX forbidden (AH01276)",
                extra=extra,
                log_upload_id=log_upload_id,
            )

        # WP embebido en apache_error_log
        wp_ev = detect_wp_from_apache_error_line(
            line=line,
            server=server,
            log_upload_id=log_upload_id,
        )
        if wp_ev:
            # No perder el host del referer si lo detectamos aquí
            if referer_host:
                try:
                    wp_extra = dict(getattr(wp_ev, "extra", None) or {})
                    wp_extra.setdefault("referer_host", referer_host)
                    wp_ev.extra = wp_extra
                except Exception:
                    pass
            return wp_ev

        # Genérico
        extra = {
            "event_type": "http_error",
            "kind": "apache_error",
        }
        if referer_host:
            extra["referer_host"] = referer_host

        return ParsedEvent(
            timestamp_utc=ts,
            server=server,
            source=self.source,
            service="HTTP",
            ip_client=ip_client,
            message=rest,
            extra=extra,
            log_upload_id=log_upload_id,
        )
