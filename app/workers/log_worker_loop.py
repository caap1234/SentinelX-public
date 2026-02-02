from __future__ import annotations

import os
import time
import traceback
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.log_upload import LogUpload
from app.services.log_pipeline import process_log_file


# -----------------------
# Settings
# -----------------------

POLL_SECONDS = int(os.getenv("WORKER_POLL_SECONDS", "2").strip() or "2")
MAX_PER_CYCLE = int(os.getenv("WORKER_MAX_PER_CYCLE", "1").strip() or "1")

# Seguridad: evita que jobs queden "processing" infinitos si el worker muere.
# Si el job lleva más de X segundos en processing, lo re-enfila como queued.
STALE_PROCESSING_SECONDS = int(os.getenv("WORKER_STALE_SECONDS", "3600").strip() or "3600")  # 1h

# Opcional: si quieres que el worker haga pausa si hay demasiados processing (protección)
MAX_PROCESSING_GLOBAL = int(os.getenv("WORKER_MAX_PROCESSING_GLOBAL", "9999").strip() or "9999")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _utcnow().isoformat()


def _requeue_stale_processing(db: Session) -> int:
    """
    Re-enfila jobs 'processing' viejos (por ejemplo si un worker se cayó).
    Usamos processing_started_at en extra_meta (lo pone el pipeline).
    Si no existe, no lo toca.
    """
    if STALE_PROCESSING_SECONDS <= 0:
        return 0

    # Esto depende de que extra_meta sea JSONB (o JSON) y el campo exista.
    # Si extra_meta no es JSONB, esta query puede fallar. En ese caso, lo hacemos en Python.
    # Vamos a hacerlo en Python para máxima compatibilidad.

    now = _utcnow()
    changed = 0

    q = db.query(LogUpload).filter(LogUpload.status == "processing")
    for job in q.limit(500).all():  # evita iterar infinito
        meta = job.extra_meta if isinstance(job.extra_meta, dict) else {}
        started = meta.get("processing_started_at")
        if not started:
            continue
        try:
            dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        age = (now - dt).total_seconds()
        if age >= STALE_PROCESSING_SECONDS:
            job.status = "queued"
            meta["worker_requeued_stale_at"] = _now_iso()
            meta["worker_requeued_reason"] = f"stale_processing>{STALE_PROCESSING_SECONDS}s"
            job.extra_meta = meta
            changed += 1

    if changed:
        db.commit()

    return changed


def _count_processing(db: Session) -> int:
    return int(db.query(LogUpload).filter(LogUpload.status == "processing").count())


def _claim_one_job(db: Session) -> Optional[Tuple[int, str, str, str]]:
    """
    Claim atómico usando SKIP LOCKED.
    - Busca 1 job queued
    - Lo marca processing
    - Devuelve (id, path, server, log_type)
    """
    # Usamos SQL crudo para garantizar FOR UPDATE SKIP LOCKED
    row = db.execute(
        text(
            """
            SELECT id
            FROM log_uploads
            WHERE status = 'queued'
            ORDER BY uploaded_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        )
    ).fetchone()

    if not row:
        return None

    upload_id = int(row[0])

    job = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
    if not job:
        return None

    meta = job.extra_meta if isinstance(job.extra_meta, dict) else {}
    log_type = str(meta.get("log_type") or "").strip()

    job.status = "processing"
    meta["worker_claimed_at"] = _now_iso()
    job.extra_meta = meta

    db.commit()
    db.refresh(job)

    return (job.id, job.path, job.server, log_type)


def _mark_error(db: Session, upload_id: int, err: str) -> None:
    job = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
    if not job:
        return
    job.status = "error"
    job.error_message = (err or "")[:4000]
    meta = job.extra_meta if isinstance(job.extra_meta, dict) else {}
    meta["worker_failed_at"] = _now_iso()
    job.extra_meta = meta
    db.commit()


def main() -> None:
    print(
        f"[worker] start poll={POLL_SECONDS}s max_per_cycle={MAX_PER_CYCLE} stale={STALE_PROCESSING_SECONDS}s",
        flush=True,
    )

    while True:
        db: Session = SessionLocal()
        try:
            # 1) opcional: requeue de trabajos atorados
            try:
                _requeue_stale_processing(db)
            except Exception as e:
                # no matar el worker por esto
                db.rollback()

            # 2) throttling global opcional
            try:
                if _count_processing(db) >= MAX_PROCESSING_GLOBAL:
                    time.sleep(POLL_SECONDS)
                    continue
            except Exception:
                db.rollback()

            did_work = False

            for _ in range(MAX_PER_CYCLE):
                claimed = _claim_one_job(db)
                if not claimed:
                    break

                did_work = True
                upload_id, file_path, server, log_type = claimed

                if not log_type:
                    _mark_error(db, upload_id, "Missing log_type in LogUpload.extra_meta")
                    continue

                try:
                    print(f"[worker] processing id={upload_id} type={log_type} path={file_path}", flush=True)

                    # Tu pipeline se encarga de marcar processed/error
                    process_log_file(
                        file_path=file_path,
                        server=server,
                        log_type=log_type,
                        upload_id=upload_id,
                    )

                except Exception as e:
                    tb = traceback.format_exc()
                    _mark_error(db, upload_id, f"{type(e).__name__}: {e}\n{tb}")

        finally:
            db.close()

        if not did_work:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

