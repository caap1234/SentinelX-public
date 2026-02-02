# scripts/resend_alert_email.py
from __future__ import annotations

import sys
from datetime import timedelta
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.alert import Alert
from app.models.event import Event
from app.models.log_upload import LogUpload


def _resolve_user_id_from_logupload(db: Session, log: LogUpload) -> Optional[int]:
    uid = getattr(log, "user_id", None)
    if uid is not None:
        try:
            return int(uid)
        except Exception:
            pass

    api_key_id = getattr(log, "api_key_id", None)
    if api_key_id:
        row = db.execute(
            text("SELECT created_by_user_id FROM api_keys WHERE id = :id"),
            {"id": int(api_key_id)},
        ).fetchone()
        if row and row[0] is not None:
            try:
                return int(row[0])
            except Exception:
                return None

    return None


def _resolve_user_id_for_alert(db: Session, alert: Alert) -> Optional[int]:
    metrics = alert.metrics if isinstance(alert.metrics, dict) else {}
    uid = metrics.get("user_id")
    if uid is not None:
        try:
            return int(uid)
        except Exception:
            pass

    evidence = alert.evidence if isinstance(alert.evidence, dict) else {}
    ev_log_upload_id = evidence.get("log_upload_id")
    if ev_log_upload_id:
        log = db.query(LogUpload).filter(LogUpload.id == int(ev_log_upload_id)).first()
        if log:
            return _resolve_user_id_from_logupload(db, log)

    if not alert.triggered_at:
        return None

    start = alert.triggered_at - timedelta(hours=2)
    end = alert.triggered_at + timedelta(hours=2)

    q = db.query(Event.id, Event.log_upload_id)

    if getattr(Event, "server", None) is not None and alert.server:
        q = q.filter(Event.server == alert.server)

    if getattr(Event, "group_key", None) is not None and alert.group_key:
        q = q.filter(Event.group_key == alert.group_key)

    q = q.filter(Event.timestamp_utc >= start, Event.timestamp_utc <= end)
    q = q.order_by(Event.timestamp_utc.desc()).limit(1)

    row = q.first()
    if not row:
        return None

    log_upload_id = row[1]
    if not log_upload_id:
        return None

    log = db.query(LogUpload).filter(LogUpload.id == int(log_upload_id)).first()
    if not log:
        return None

    return _resolve_user_id_from_logupload(db, log)


def main() -> int:
    if len(sys.argv) != 2:
        print("USO: python -m scripts.resend_alert_email <alert_id>")
        return 2

    alert_id = int(sys.argv[1])

    from app.services.notification_dispatch import notify_on_alert_created
    from app.services.emailer import smtp_configured

    if not smtp_configured():
        print("❌ SMTP no configurado (SMTP_HOST/SMTP_PORT/FROM_EMAIL).")
        return 1

    db: Session = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            print(f"❌ Alerta {alert_id} no encontrada.")
            return 1

        user_id = _resolve_user_id_for_alert(db, alert)
        if not user_id:
            print(f"❌ No se pudo resolver user_id para la alerta {alert_id}.")
            print("   Sugerencia: guardar user_id/log_upload_id en alert.metrics/evidence al crear la alerta.")
            return 1

        notify_on_alert_created(db=db, alert=alert, user_id=int(user_id))
        db.commit()

        print(f"✅ Reenvío OK via notification_dispatch (alert_id={alert_id}, user_id={user_id}).")
        return 0

    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

