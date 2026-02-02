# app/core/enums.py
from enum import Enum
from typing import Dict


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityLevel:
    # Guardado en DB
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_STR_TO_INT: Dict[str, int] = {
    "low": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL,
}

SEVERITY_ENUM_TO_INT: Dict[Severity, int] = {
    Severity.LOW: SeverityLevel.LOW,
    Severity.MEDIUM: SeverityLevel.MEDIUM,
    Severity.HIGH: SeverityLevel.HIGH,
    Severity.CRITICAL: SeverityLevel.CRITICAL,
}

SEVERITY_INT_TO_ENUM: Dict[int, Severity] = {
    SeverityLevel.LOW: Severity.LOW,
    SeverityLevel.MEDIUM: Severity.MEDIUM,
    SeverityLevel.HIGH: Severity.HIGH,
    SeverityLevel.CRITICAL: Severity.CRITICAL,
}


class CorrelationScope(str, Enum):
    LOCAL = "local"
    GLOBAL = "global"


class LogSource(str, Enum):
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    EXIM_MAINLOG = "exim_mainlog"
    EXIM_REJECTLOG = "exim_rejectlog"
    DOVECOT = "dovecot"
    PANEL = "panel"
    FILEMANAGER = "filemanager"
    WP_ERROR = "wp_error_log"
    SSH_SECURE = "secure_log"
    LFD = "lfd_log"
    SYSTEM = "system_log"
    MODSEC = "modsec_audit"
    OTHER = "other"
    SAR_STATS = "sar_stats"


class Service(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    PANEL = "panel"
    WORDPRESS = "wordpress"
    SYSTEM = "system"
    MAIL = "mail"
    UNKNOWN = "unknown"
    INFRA = "infra"


# ---------------------------------------------------------------------
# ✅ NUEVO: status + clasificación de resolución (validación API / UI)
# ---------------------------------------------------------------------
class EventStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EventDisposition(str, Enum):
    INFORMATIONAL = "informational"
    BENIGN = "benign"
    TRUE_POSITIVE = "true_positive"
    MITIGATED = "mitigated"
    NEEDS_FOLLOWUP = "needs_followup"


class EventCategory(str, Enum):
    BOT = "bot"
    DDOS = "ddos"
    SPAM = "spam"
    SCANNING = "scanning"
    WEB_ABUSE = "web_abuse"
    MAIL_ABUSE = "mail_abuse"
    BRUTE_FORCE = "brute_force"
    OTHER = "other"
