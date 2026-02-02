# app/services/emailer.py
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional, Tuple


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        v = int(raw)
        return v if v > 0 else default
    except Exception:
        return default


def smtp_configured() -> bool:
    host = _env("SMTP_HOST")
    port = _env("SMTP_PORT")
    from_email = _env("FROM_EMAIL")
    return bool(host and port and from_email)


def _build_message(*, to_email: str, subject: str, text_body: str, html_body: Optional[str]) -> EmailMessage:
    from_email = _env("FROM_EMAIL")

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject

    if html_body:
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")
    else:
        msg.set_content(text_body)

    return msg


def _send_via_smtps_465(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    msg: EmailMessage,
    timeout_sec: int,
) -> None:
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(host, port, timeout=timeout_sec, context=context) as s:
        s.ehlo_or_helo_if_needed()
        s.login(user, password)
        s.send_message(msg)


def _send_via_smtp_587(
    *,
    host: str,
    port: int,
    user: str,
    password: str,
    msg: EmailMessage,
    timeout_sec: int,
) -> None:
    with smtplib.SMTP(host, port, timeout=timeout_sec) as s:
        # ayuda con SNI si se llegara a usar TLS
        s._host = host  # type: ignore[attr-defined]
        s.ehlo()

        # SOLO STARTTLS si el server lo anuncia
        if s.has_extn("starttls"):
            context = ssl.create_default_context()
            s.starttls(context=context)
            s.ehlo()

        features = getattr(s, "esmtp_features", {}) or {}
        if "auth" not in features:
            raise smtplib.SMTPNotSupportedError("SMTP AUTH extension not supported by server")

        s.login(user, password)
        s.send_message(msg)


def send_email(
    *,
    to_email: str,
    subject: str,
    text_body: str,
    html_body: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Envío SMTP autenticado (requerido):
    - Retorna (ok, error_message)
    - Intenta 465 primero, si falla hace fallback a 587.
    """
    if not smtp_configured():
        return (False, "SMTP not configured (SMTP_HOST/SMTP_PORT/FROM_EMAIL)")

    host = _env("SMTP_HOST")
    user = _env("SMTP_USER")
    password = _env("SMTP_PASS")

    if not (user and password):
        return (False, "SMTP_USER/SMTP_PASS missing (AUTH required)")

    timeout_sec = _env_int("SMTP_TIMEOUT_SECONDS", 60)

    # puerto preferido desde env (normalmente 465)
    preferred_port = int(_env("SMTP_PORT", "465") or "465")

    msg = _build_message(to_email=to_email, subject=subject, text_body=text_body, html_body=html_body)

    # Orden de intentos:
    # - Si prefieren 465 => 465 luego 587
    # - Si prefieren 587 => 587 luego 465
    attempts = []
    if preferred_port == 587:
        attempts = [("smtp", 587), ("smtps", 465)]
    else:
        attempts = [("smtps", 465), ("smtp", 587)]

    last_err: Optional[str] = None

    for mode, port in attempts:
        try:
            if mode == "smtps":
                _send_via_smtps_465(host=host, port=port, user=user, password=password, msg=msg, timeout_sec=timeout_sec)
                return (True, None)

            _send_via_smtp_587(host=host, port=port, user=user, password=password, msg=msg, timeout_sec=timeout_sec)
            return (True, None)

        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            # log simple a stdout para docker logs
            print(f"[emailer] send failed mode={mode} host={host} port={port} err={last_err}", flush=True)

    return (False, last_err or "unknown error")

