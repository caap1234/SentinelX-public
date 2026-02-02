# app/services/raw_policy.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.parsing.types import ParsedEvent


@dataclass(frozen=True)
class RawPolicyDecision:
    store: bool
    source_hint: str


class RawPolicy:
    """
    Decide si guardamos raw en rawlogs para un evento parseado.

    Reglas acordadas:
    - Guardar raw siempre (bajo volumen / acciones admin):
      lfd, modsec, secure, system_secure, cpanel_access, filemanager, panel_logs
    - exim_mainlog: solo eventos de interés (rejects, bounces, auth fails, etc.)
    - access_log: raw solo si es interesante (4xx/5xx, wp-login/xmlrpc, paths sensibles, bots raros)
      + PERO: filtrar ruido (whm-server-status/server-status, healthchecks, etc.)
    - system: raw solo si es interesante o debug temporal (ssh/sudo/csf/kernel oom, etc.)
    - apache_error: raw NO si noise; si no es noise lo guardamos
    - sar:
        * guardar raw si load (metric.name=load) y ldavg_1 >= 6
        * guardar raw si memory (metric.name=memory) y mem_used_pct >= 92
    - maillog_dovecot:
        * guardar raw SOLO si extra.event_type == auth_login (para evidencia)

    Nota práctica:
    - Shippers suelen mandar log_type como: "maillog", "mail", "auth", etc.
      Este policy hace alias + autodetección para que no se pierda raw en reglas AUTH/MAIL.
    """

    ALWAYS = {
        "lfd",
        "modsec",
        "secure",
        "system_secure",
        "cpanel_access",
        "filemanager",
        "panel_logs",
    }

    SENSITIVE_PATH_HINTS = (
        "/wp-login.php",
        "/xmlrpc.php",
        "/wp-admin",
        "/.env",
        "/.git",
        "/phpmyadmin",
        "/admin",
        "/login",
    )

    IGNORE_PATH_HINTS = (
        "/whm-server-status",
        "/whm-server-status?auto",
        "/server-status",
        "/server-status?auto",
        "/whm-server-status/",
        "/server-status/",
    )

    LOOPBACK_IPS = {"127.0.0.1", "::1"}

    SUSPICIOUS_UA_HINTS = (
        "python-requests",
        "python-httpx",
        "go-http-client",
        "curl/",
        "wget/",
        "masscan",
        "zgrab",
        "sqlmap",
        "nikto",
    )

    SYSTEM_INTERESTING_HINTS = (
        "sshd",
        "sudo",
        "authentication failure",
        "failed password",
        "invalid user",
        "csf",
        "lfd",
        "oom-killer",
        "out of memory",
        "kernel:",
        "segfault",
        "imunify",
        "modsecurity",
    )

    _MAIL_ALIASES = {
        # exim
        "exim": "exim_mainlog",
        "exim4": "exim_mainlog",
        "exim_main": "exim_mainlog",
        # dovecot
        "dovecot_auth": "dovecot",
        "mailauth": "dovecot",
        # generic
        "mail": "maillog",
        "maillog": "maillog",
        "auth": "auth",
    }

    def _is_dovecot_like(self, *, log_type_norm: str, pe: ParsedEvent) -> bool:
        if log_type_norm in ("maillog_dovecot", "dovecot", "auth"):
            return True

        src = str(getattr(pe, "source", "") or "").strip().lower()
        if "dovecot" in src:
            return True

        extra = pe.extra or {}
        if isinstance(extra, dict):
            proc = str(extra.get("process") or extra.get("program") or extra.get("daemon") or "").lower()
            if "dovecot" in proc:
                return True

        msg = str(pe.message or "").lower()
        # heurística: líneas de auth dovecot suelen traer "imap-login"/"pop3-login"/"auth"
        if "dovecot" in msg or "imap-login" in msg or "pop3-login" in msg:
            return True

        return False

    def _is_exim_like(self, *, log_type_norm: str, pe: ParsedEvent) -> bool:
        if log_type_norm in ("exim_mainlog",):
            return True

        src = str(getattr(pe, "source", "") or "").strip().lower()
        if "exim" in src:
            return True

        extra = pe.extra or {}
        if isinstance(extra, dict):
            proc = str(extra.get("process") or extra.get("program") or extra.get("daemon") or "").lower()
            if "exim" in proc:
                return True

        msg = str(pe.message or "").lower()
        if " exim" in msg or msg.startswith("exim") or "exim_mainlog" in msg:
            return True

        return False

    def decide(self, *, log_type: str, raw_line: str, pe: Optional[ParsedEvent]) -> RawPolicyDecision:
        original = (log_type or "").strip()
        log_type_norm = original.lower()
        source_hint = original or log_type_norm

        if pe is None:
            return RawPolicyDecision(store=False, source_hint=source_hint)

        # ---- normalize aliases ----
        log_type_norm = self._MAIL_ALIASES.get(log_type_norm, log_type_norm)

        if log_type_norm in self.ALWAYS:
            return RawPolicyDecision(store=True, source_hint=source_hint)

        # -------------------------
        # Dovecot / AUTH (robusto)
        # -------------------------
        if self._is_dovecot_like(log_type_norm=log_type_norm, pe=pe):
            extra = pe.extra or {}
            if not isinstance(extra, dict):
                return RawPolicyDecision(store=False, source_hint=source_hint)

            # La regla acordada: guardar raw SOLO si es auth_login
            if str(extra.get("event_type") or "").strip().lower() != "auth_login":
                return RawPolicyDecision(store=False, source_hint=source_hint)

            # Si viene action, limitamos a success/fail (si no viene, auth_login ya es suficiente)
            action = str(extra.get("action") or "").strip().lower()
            if action in ("success", "ok", "passed", "fail", "failed"):
                return RawPolicyDecision(store=True, source_hint=source_hint)

            return RawPolicyDecision(store=True, source_hint=source_hint)

        # -------------
        # SAR
        # -------------
        if log_type_norm == "sar":
            try:
                extra = pe.extra or {}
                if not isinstance(extra, dict):
                    return RawPolicyDecision(store=False, source_hint=source_hint)

                if str(extra.get("event_type") or "").strip().lower() != "metric":
                    return RawPolicyDecision(store=False, source_hint=source_hint)

                metric = extra.get("metric")
                if not isinstance(metric, dict):
                    return RawPolicyDecision(store=False, source_hint=source_hint)

                name = str(metric.get("name") or "").strip().lower()

                # sar -q
                if name == "load":
                    ld1 = metric.get("ldavg_1")
                    if ld1 is None:
                        ld1 = metric.get("ldavg_1_per_cpu")
                    try:
                        ld1_f = float(ld1)
                    except Exception:
                        return RawPolicyDecision(store=False, source_hint=source_hint)

                    return RawPolicyDecision(store=(ld1_f >= 6.0), source_hint=source_hint)

                # sar -r
                if name == "memory":
                    mem = metric.get("mem_used_pct")
                    try:
                        mem_f = float(mem)
                    except Exception:
                        return RawPolicyDecision(store=False, source_hint=source_hint)

                    return RawPolicyDecision(store=(mem_f >= 92.0), source_hint=source_hint)

                return RawPolicyDecision(store=False, source_hint=source_hint)

            except Exception:
                return RawPolicyDecision(store=False, source_hint=source_hint)

        # ----------------
        # Apache access
        # ----------------
        if log_type_norm == "apache_access":
            status: Optional[int] = None
            path = ""
            ua = ""
            ip = None

            try:
                http = (pe.extra or {}).get("http") or {}
                status = int(http.get("status")) if http.get("status") is not None else None
                path = str(http.get("path") or "")
                ua = str(http.get("user_agent") or "").lower()
                ip = getattr(pe, "ip_client", None)
            except Exception:
                pass

            low_path = (path or "").lower()

            if any(h in low_path for h in self.IGNORE_PATH_HINTS):
                return RawPolicyDecision(store=False, source_hint=source_hint)

            if status is not None and status >= 400:
                return RawPolicyDecision(store=True, source_hint=source_hint)

            if any(h in low_path for h in self.SENSITIVE_PATH_HINTS):
                return RawPolicyDecision(store=True, source_hint=source_hint)

            if any(h in ua for h in self.SUSPICIOUS_UA_HINTS):
                ip_txt = str(ip) if ip is not None else ""
                if ip_txt in self.LOOPBACK_IPS:
                    return RawPolicyDecision(store=False, source_hint=source_hint)
                return RawPolicyDecision(store=True, source_hint=source_hint)

            return RawPolicyDecision(store=False, source_hint=source_hint)

        # ----------------
        # Exim mainlog (robusto)
        # ----------------
        if self._is_exim_like(log_type_norm=log_type_norm, pe=pe):
            extra = pe.extra or {}
            if not isinstance(extra, dict):
                extra = {}

            direction = (extra.get("direction") or "").lower()
            auth_success = extra.get("auth_success")

            msg = (pe.message or "").lower()
            interesting = any(
                kw in msg
                for kw in (
                    "rejected",
                    "reject",
                    "deny",
                    "bounced",
                    "bounce",
                    "deferred",
                    "defer",
                    "spam",
                    "blacklist",
                    "rbl",
                    "authentication failed",
                    "auth failed",
                    "failed authentication",
                )
            )

            if direction in ("in", "out") and interesting:
                return RawPolicyDecision(store=True, source_hint=source_hint)
            if auth_success is False:
                return RawPolicyDecision(store=True, source_hint=source_hint)

            return RawPolicyDecision(store=False, source_hint=source_hint)

        # -------------
        # System
        # -------------
        if log_type_norm == "system":
            msg = (pe.message or "").lower()
            proc = str((pe.extra or {}).get("process") or "").lower()

            joined = f"{proc} {msg}"
            if any(h in joined for h in self.SYSTEM_INTERESTING_HINTS):
                return RawPolicyDecision(store=True, source_hint=source_hint)

            return RawPolicyDecision(store=False, source_hint=source_hint)

        # ----------------
        # Apache error
        # ----------------
        if log_type_norm == "apache_error":
            extra = pe.extra or {}
            if isinstance(extra, dict) and extra.get("noise") is True:
                return RawPolicyDecision(store=False, source_hint=source_hint)
            return RawPolicyDecision(store=True, source_hint=source_hint)

        return RawPolicyDecision(store=False, source_hint=source_hint)
