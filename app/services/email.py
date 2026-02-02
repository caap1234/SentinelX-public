from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Optional

from app.config import settings

logger = logging.getLogger("sentinelx.email")


def _smtp_enabled() -> bool:
    return bool(getattr(settings, "SMTP_HOST", None) and getattr(settings, "SMTP_PORT", None))


def send_email_safe(to_email: str, subject: str, body: str) -> bool:
    """
    Envía email. Si falla:
      - NO lanza excepción
      - regresa False
      - deja log
    """
    try:
        if not _smtp_enabled():
            logger.warning("SMTP no configurado (SMTP_HOST/SMTP_PORT). Email omitido. subject=%s to=%s", subject, to_email)
            return False

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = getattr(settings, "FROM_EMAIL", "sentinelx@localhost")
        msg["To"] = to_email
        msg.set_content(body)

        host = settings.SMTP_HOST
        port = int(settings.SMTP_PORT)
        user = getattr(settings, "SMTP_USER", None)
        password = getattr(settings, "SMTP_PASS", None)

        with smtplib.SMTP(host, port, timeout=15) as s:
            s.ehlo()
            # STARTTLS si es 587 normalmente
            try:
                s.starttls()
                s.ehlo()
            except Exception:
                # si el server no soporta starttls, seguimos (no tronamos)
                logger.warning("SMTP sin STARTTLS o fallo STARTTLS. host=%s port=%s", host, port)

            if user and password:
                s.login(user, password)

            s.send_message(msg)

        return True

    except Exception as e:
        logger.exception("Fallo enviando email. to=%s subject=%s error=%s", to_email, subject, str(e))
        return False


def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    base_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:4321")
    link = f"{base_url}/reset-password?token={reset_token}"

    subject = "Recuperación de contraseña - SentinelX"
    body = (
        "Se solicitó un restablecimiento de contraseña.\n\n"
        f"Abre este enlace para continuar:\n{link}\n\n"
        "Si no fuiste tú, ignora este correo."
    )
    return send_email_safe(to_email, subject, body)
