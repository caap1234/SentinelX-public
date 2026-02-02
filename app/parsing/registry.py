# app/parsing/registry.py
from __future__ import annotations

from typing import Dict, Optional

from app.parsing.base import LogParser
from app.parsing.types import ParsedEvent

from app.parsing.apache_access import ApacheAccessParser
from app.parsing.apache_error_log import ApacheErrorLogParser
from app.parsing.nginx_access import NginxAccessParser  # <-- NUEVO
from app.parsing.cpanel_access import CPanelAccessParser
from app.parsing.exim_mainlog import EximMainlogParser
from app.parsing.lfd_log import LfdLogParser
from app.parsing.modsec_audit import ModSecAuditParser
from app.parsing.panel_logs import PanelLogParser
from app.parsing.sar_stats import SarStatsParser
from app.parsing.system_logs import SystemLogParser
from app.parsing.system_secure import SecureLogParser
from app.parsing.wp_error_log import WpErrorLogParser
from app.parsing.maillog_dovecot import MaillogDovecotParser


# Nota: wp_from_apache_error lo usa ApacheErrorLogParser internamente

DEFAULT_PARSERS: Dict[str, LogParser] = {
    "APACHE_ACCESS": ApacheAccessParser(),
    "NGINX_ACCESS": NginxAccessParser(),  # <-- NUEVO (domlogs nginx /var/log/nginx/domains/*)
    "APACHE_ERROR": ApacheErrorLogParser(),
    "PANEL_ACCESS": CPanelAccessParser(),     # access_log de cPanel (apache-like)
    "PANEL_LOGIN": PanelLogParser(),          # login_log simplificado (si lo usas)
    "EXIM_MAINLOG": EximMainlogParser(),
    "MAILLOG": MaillogDovecotParser(),
    "LFD": LfdLogParser(),
    "MODSEC": ModSecAuditParser(),
    "SAR_STATS": SarStatsParser(),
    "SYSTEM": SystemLogParser(),
    "SSH_SECURE": SecureLogParser(),
    "WP_ERROR": WpErrorLogParser(),
}


def get_parser(source_hint: str) -> Optional[LogParser]:
    return DEFAULT_PARSERS.get((source_hint or "").strip().upper())


def parse_line(
    source_hint: str,
    line: str,
    server: str,
    *,
    log_upload_id: Optional[int] = None,
) -> Optional[ParsedEvent]:
    parser = get_parser(source_hint)
    if not parser:
        return None
    return parser.parse_line(line, server, log_upload_id=log_upload_id)
