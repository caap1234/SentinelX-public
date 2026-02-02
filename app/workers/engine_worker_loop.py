# app/workers/engine_worker_loop.py
from __future__ import annotations

import os
import time
import traceback
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.event import Event
from app.models.log_upload import LogUpload
from app.models.system_setting import SystemSetting
from app.services.rule_engine_runtime import get_rule_engine, invalidate_rule_engine_cache

try:
    from sqlalchemy.orm.exc import DetachedInstanceError
except Exception:  # pragma: no cover
    DetachedInstanceError = Exception  # type: ignore


POLL_SECONDS_ENV = int(os.getenv("ENGINE_WORKER_POLL_SECONDS", "1").strip() or "1")
MAX_PER_CYCLE_ENV = int(os.getenv("ENGINE_WORKER_MAX_PER_CYCLE", "200").strip() or "200")
STALE_PROCESSING_SECONDS_ENV = int(os.getenv("ENGINE_WORKER_STALE_SECONDS", "3600").strip() or "3600")
RECONCILE_EVERY_CYCLES_ENV = int(os.getenv("ENGINE_WORKER_RECONCILE_EVERY", "10").strip() or "10")

# system_settings keys
KEY_ENABLED = "pipeline.engine.enabled"
KEY_MAX_PER_CYCLE = "pipeline.engine.max_per_cycle"
KEY_POLL_SECONDS = "pipeline.engine.poll_seconds"
KEY_STALE_SECONDS = "pipeline.engine.stale_seconds"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _utcnow().isoformat()


def _get_setting(db: Session, key: str) -> Optional[str]:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row else None


def _get_bool(db: Session, key: str, default: bool) -> bool:
    raw = (_get_setting(db, key) or ("1" if default else "0")).strip().lower()
    return raw in ("1", "true", "yes", "y", "on", "enabled")


def _get_int(db: Session, key: str, default: int) -> int:
    raw = (_get_setting(db, key) or str(default)).strip()
    try:
        return int(raw)
    except Exception:
        return int(default)


def _requeue_stale_engine(db: Session, stale_seconds: int) -> int:
    if stale_seconds <= 0:
        return 0

    cutoff = _utcnow() - timedelta(seconds=int(stale_seconds))

    res = db.execute(
        text(
            """
            WITH cte AS (
              SELECT id
              FROM events
              WHERE engine_status = 'processing'
                AND engine_claimed_at IS NOT NULL
                AND engine_claimed_at < :cutoff
              ORDER BY engine_claimed_at ASC
              LIMIT 1000
              FOR UPDATE SKIP LOCKED
            )
            UPDATE events e
            SET engine_status = 'pending',
                engine_claimed_at = NULL,
                engine_error = :msg
            FROM cte
            WHERE e.id = cte.id
            RETURNING e.id
            """
        ),
        {"cutoff": cutoff, "msg": f"stale_processing>{stale_seconds}s requeued at {_now_iso()}"},
    )
    return len(res.fetchall())


def _claim_one_event(db: Session) -> Optional[Tuple[UUID, Optional[int]]]:
    res = db.execute(
        text(
            """
            WITH cte AS (
              SELECT id
              FROM events
              WHERE engine_status = 'pending'
              ORDER BY created_at ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE events e
            SET engine_status = 'processing',
                engine_claimed_at = :now,
                engine_attempts = COALESCE(engine_attempts, 0) + 1,
                engine_error = NULL
            FROM cte
            WHERE e.id = cte.id
            RETURNING e.id, e.log_upload_id
            """
        ),
        {"now": _utcnow()},
    ).fetchone()

    if not res:
        return None

    return (res[0], res[1])


def _maybe_mark_upload_processed(db: Session, upload_id: int) -> None:
    if not upload_id:
        return

    still = (
        db.query(Event.id)
        .filter(
            Event.log_upload_id == upload_id,
            Event.engine_status.in_(["pending", "processing"]),
        )
        .limit(1)
        .first()
    )
    if still:
        return

    log = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
    if not log:
        return

    if log.status in ("parsed", "processing_engine", "parsing"):
        log.status = "processed"
        meta = log.extra_meta if isinstance(log.extra_meta, dict) else {}
        meta["engine_finished_at"] = _now_iso()
        log.extra_meta = meta


def _reconcile_uploads_processing_engine(db: Session, limit: int = 500) -> int:
    res = db.execute(
        text(
            """
            WITH cte AS (
              SELECT lu.id
              FROM log_uploads lu
              WHERE lu.status = 'processing_engine'
                AND NOT EXISTS (
                  SELECT 1
                  FROM events e
                  WHERE e.log_upload_id = lu.id
                    AND e.engine_status IN ('pending','processing')
                )
              ORDER BY lu.uploaded_at DESC
              LIMIT :limit
              FOR UPDATE SKIP LOCKED
            )
            UPDATE log_uploads lu
            SET status = 'processed',
                extra_meta = COALESCE(lu.extra_meta, '{}'::jsonb) ||
                           jsonb_build_object('engine_finished_at', :now)
            FROM cte
            WHERE lu.id = cte.id
            RETURNING lu.id
            """
        ),
        {"limit": int(limit), "now": _now_iso()},
    )
    return len(res.fetchall())


def _mark_event_error(db: Session, event_id: UUID, err: str) -> None:
    ev = db.query(Event).filter(Event.id == event_id).first()
    if not ev:
        return
    ev.engine_status = "error"
    ev.engine_processed_at = _utcnow()
    ev.engine_error = (err or "")[:8000]


def _mark_event_done(db: Session, event_id: UUID) -> None:
    ev = db.query(Event).filter(Event.id == event_id).first()
    if not ev:
        return
    ev.engine_status = "done"
    ev.engine_processed_at = _utcnow()
    ev.engine_error = None


def _resolve_user_id_for_notify(db: Session, log: Optional[LogUpload]) -> Optional[int]:
    """
    user_id directo si existe en log_uploads; si no, resolver por api_keys.created_by_user_id
    """
    if log is None:
        return None

    uid = getattr(log, "user_id", None)

    if uid is None:
        api_key_id = getattr(log, "api_key_id", None)
        if api_key_id:
            row = db.execute(
                text("SELECT created_by_user_id FROM api_keys WHERE id = :id"),
                {"id": int(api_key_id)},
            ).fetchone()
            if row:
                uid = row[0]

    try:
        return int(uid) if uid is not None else None
    except Exception:
        return None


def _notify_alerts_post_commit(*, alert_ids: List, user_id: int) -> None:
    """
    Notifica alertas FUERA de la transacción del engine.
    Usa el notifier real del proyecto: app.services.notification_dispatch
    """
    if not alert_ids or not user_id:
        return

    try:
        from app.models.alert import Alert
    except Exception as e:
        print(f"[engine-worker] Alert model import failed: {type(e).__name__}: {e}", flush=True)
        return

    try:
        from app.services.notification_dispatch import notify_on_alert_created, smtp_configured  # type: ignore
    except Exception as e:
        tb = traceback.format_exc()
        print(
            f"[engine-worker] notifier import failed (notification_dispatch): {type(e).__name__}: {e}\n{tb}",
            flush=True,
        )
        return

    if not smtp_configured():
        # Esto explica exactamente por qué "no llega correo" aunque todo lo demás esté bien
        print("[engine-worker] SMTP no configurado (SMTP_HOST/SMTP_PORT/FROM_EMAIL). Notificaciones omitidas.", flush=True)
        return

    dbn: Session = SessionLocal()
    try:
        for aid in alert_ids:
            if not aid:
                continue
            al = dbn.query(Alert).filter(Alert.id == aid).first()
            if not al:
                continue
            try:
                notify_on_alert_created(db=dbn, alert=al, user_id=user_id)
            except Exception as e:
                print(f"[engine-worker] notify failed alert_id={aid} user_id={user_id}: {type(e).__name__}: {e}", flush=True)
                # no tumbar el worker por correo
                pass
    finally:
        dbn.close()


def main() -> None:
    print(
        f"[engine-worker] start poll={POLL_SECONDS_ENV}s max_per_cycle={MAX_PER_CYCLE_ENV} stale={STALE_PROCESSING_SECONDS_ENV}s",
        flush=True,
    )

    engine = get_rule_engine()
    cycle = 0

    while True:
        did_work = False

        poll_seconds = POLL_SECONDS_ENV
        max_per_cycle = MAX_PER_CYCLE_ENV
        stale_seconds = STALE_PROCESSING_SECONDS_ENV

        db: Session = SessionLocal()
        try:
            enabled = _get_bool(db, KEY_ENABLED, default=True)
            poll_seconds = max(1, _get_int(db, KEY_POLL_SECONDS, default=POLL_SECONDS_ENV))
            max_per_cycle = max(1, _get_int(db, KEY_MAX_PER_CYCLE, default=MAX_PER_CYCLE_ENV))
            stale_seconds = max(0, _get_int(db, KEY_STALE_SECONDS, default=STALE_PROCESSING_SECONDS_ENV))

            if not enabled:
                time.sleep(poll_seconds)
                continue

            # Requeue stale (tx corta)
            try:
                with db.begin():
                    _requeue_stale_engine(db, stale_seconds=stale_seconds)
            except Exception:
                db.rollback()

            # Reconciliación periódica de uploads pegados
            cycle += 1
            if RECONCILE_EVERY_CYCLES_ENV > 0 and (cycle % RECONCILE_EVERY_CYCLES_ENV) == 0:
                try:
                    with db.begin():
                        fixed = _reconcile_uploads_processing_engine(db, limit=500)
                    if fixed:
                        print(f"[engine-worker] reconciled uploads fixed={fixed}", flush=True)
                except Exception:
                    db.rollback()

            for _ in range(max_per_cycle):
                claimed: Optional[Tuple[UUID, Optional[int]]] = None
                try:
                    with db.begin():
                        claimed = _claim_one_event(db)
                except Exception:
                    db.rollback()
                    claimed = None

                if not claimed:
                    break

                did_work = True
                event_id, upload_id = claimed

                alert_ids_to_notify: List = []
                notify_user_id: Optional[int] = None

                try:
                    with db.begin():
                        ev = db.query(Event).filter(Event.id == event_id).first()
                        if not ev:
                            continue

                        log: Optional[LogUpload] = None
                        if upload_id:
                            log = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
                            if log and log.status in ("parsed", "parsing"):
                                log.status = "processing_engine"
                                meta = log.extra_meta if isinstance(log.extra_meta, dict) else {}
                                meta.setdefault("engine_started_at", _now_iso())
                                log.extra_meta = meta

                        created_alerts = None
                        try:
                            created_alerts = engine.on_event(db, ev)
                        except DetachedInstanceError as e:
                            print(f"[engine-worker] DetachedInstanceError -> hard reload + retry: {e}", flush=True)
                            invalidate_rule_engine_cache(hard=True)
                            engine = get_rule_engine()
                            created_alerts = engine.on_event(db, ev)

                        db.flush()

                        notify_user_id = _resolve_user_id_for_notify(db, log)

                        for a in (created_alerts or []):
                            aid = getattr(a, "id", None)
                            if aid is not None:
                                alert_ids_to_notify.append(aid)

                        _mark_event_done(db, event_id)

                        if upload_id:
                            _maybe_mark_upload_processed(db, upload_id)

                    # Fuera de la tx: notifica
                    if alert_ids_to_notify and notify_user_id:
                        _notify_alerts_post_commit(alert_ids=alert_ids_to_notify, user_id=int(notify_user_id))
                    elif alert_ids_to_notify and not notify_user_id:
                        print(
                            f"[engine-worker] alerts created but no user_id resolved event_id={event_id} upload_id={upload_id}",
                            flush=True,
                        )

                except Exception as e:
                    tb = traceback.format_exc()
                    err = f"{type(e).__name__}: {e}\n{tb}"
                    try:
                        with db.begin():
                            _mark_event_error(db, event_id, err)
                    except Exception:
                        db.rollback()

        finally:
            db.close()

        if not did_work:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    main()

