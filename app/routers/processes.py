from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models.alert import Alert
from app.models.event import Event
from app.models.incident import Incident
from app.models.log_upload import LogUpload
from app.services.system_settings_service import SystemSettingsService

router = APIRouter(prefix="/processes", tags=["Processes"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_settings = SystemSettingsService(ttl_seconds=5)

# Keys “pro” (UI control plane)
KEY_PARSING_ENABLED = "pipeline.parsing.enabled"
KEY_ENGINE_ENABLED = "pipeline.engine.enabled"
KEY_PARSING_MAX_PER_CYCLE = "pipeline.parsing.max_per_cycle"
KEY_ENGINE_MAX_PER_CYCLE = "pipeline.engine.max_per_cycle"
KEY_PARSING_POLL_SECONDS = "pipeline.parsing.poll_seconds"
KEY_ENGINE_POLL_SECONDS = "pipeline.engine.poll_seconds"

KEY_ENTITIES_JOB_ENABLED = "jobs.entities.enabled"
KEY_INCIDENTS_JOB_ENABLED = "jobs.incidents.enabled"


def _count_by_status(db: Session) -> Dict[str, int]:
    rows = (
        db.query(LogUpload.status, func.count(LogUpload.id))
        .group_by(LogUpload.status)
        .all()
    )
    out: Dict[str, int] = {}
    for st, n in rows:
        out[str(st or "")] = int(n or 0)
    return out


def _count_events_by_engine_status(db: Session) -> Dict[str, int]:
    """
    IMPORTANTE:
    Contar TODA la tabla events con GROUP BY provoca Parallel Seq Scan (carísimo en I/O)
    cuando events crece. Para "processes overview" solo interesa la cola operativa.
    """
    tracked = ["pending", "processing", "error"]

    rows = (
        db.query(Event.engine_status, func.count(Event.id))
        .filter(Event.engine_status.in_(tracked))
        .group_by(Event.engine_status)
        .all()
    )

    out: Dict[str, int] = {k: 0 for k in tracked}
    for st, n in rows:
        key = str(st or "")
        if key in out:
            out[key] = int(n or 0)
    return out


def _oldest_upload_in_status(db: Session, status: str) -> Optional[str]:
    row = (
        db.query(LogUpload.uploaded_at)
        .filter(LogUpload.status == status)
        .order_by(LogUpload.uploaded_at.asc())
        .first()
    )
    if not row or not row[0]:
        return None
    dt: datetime = row[0]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _oldest_pending_event(db: Session) -> Optional[str]:
    row = (
        db.query(Event.created_at)
        .filter(Event.engine_status == "pending")
        .order_by(Event.created_at.asc())
        .first()
    )
    if not row or not row[0]:
        return None
    dt: datetime = row[0]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# Cache muy corto para evitar que el front (polling) dispare queries pesadas repetidas.
# Compartido global (control-plane), TTL pequeño.
_OVERVIEW_CACHE: Dict[str, Any] = {"ts": 0.0, "data": None}
_OVERVIEW_TTL_SECONDS = 2.0


@router.get("/overview")
def processes_overview(db: Session = Depends(get_db)) -> Dict[str, Any]:
    now = _utcnow()

    # cache (2s) para evitar thundering herd del polling
    tnow = time.time()
    cached = _OVERVIEW_CACHE.get("data")
    ts = float(_OVERVIEW_CACHE.get("ts") or 0.0)
    if cached and (tnow - ts) < _OVERVIEW_TTL_SECONDS:
        return cached

    last_24h = now - timedelta(hours=24)

    uploads_by_status = _count_by_status(db)
    events_by_status = _count_events_by_engine_status(db)

    alerts_24h = int(
        db.query(func.count(Alert.id))
        .filter(Alert.created_at >= last_24h)
        .scalar()
        or 0
    )

    incidents_24h = int(
        db.query(func.count(Incident.id))
        .filter(Incident.created_at >= last_24h)
        .scalar()
        or 0
    )

    # tablas “operativas” (últimos pendientes / errores)
    pending_uploads = (
        db.query(LogUpload)
        .filter(
            LogUpload.status.in_(
                ["queued", "parsing", "parsed", "processing_engine"]
            )
        )
        .order_by(LogUpload.uploaded_at.asc())
        .limit(50)
        .all()
    )

    error_uploads = (
        db.query(LogUpload)
        .filter(LogUpload.status == "error")
        .order_by(LogUpload.uploaded_at.desc())
        .limit(30)
        .all()
    )

    pending_events = (
        db.query(Event)
        .filter(Event.engine_status.in_(["pending", "processing", "error"]))
        .order_by(Event.created_at.asc())
        .limit(80)
        .all()
    )

    settings = {
        KEY_PARSING_ENABLED: "1"
        if _settings.get_bool(db, KEY_PARSING_ENABLED, default=True)
        else "0",
        KEY_ENGINE_ENABLED: "1"
        if _settings.get_bool(db, KEY_ENGINE_ENABLED, default=True)
        else "0",
        KEY_PARSING_MAX_PER_CYCLE: str(
            _settings.get_int(db, KEY_PARSING_MAX_PER_CYCLE, default=0)
        )
        or "",
        KEY_ENGINE_MAX_PER_CYCLE: str(
            _settings.get_int(db, KEY_ENGINE_MAX_PER_CYCLE, default=0)
        )
        or "",
        KEY_PARSING_POLL_SECONDS: str(
            _settings.get_int(db, KEY_PARSING_POLL_SECONDS, default=0)
        )
        or "",
        KEY_ENGINE_POLL_SECONDS: str(
            _settings.get_int(db, KEY_ENGINE_POLL_SECONDS, default=0)
        )
        or "",
        KEY_ENTITIES_JOB_ENABLED: "1"
        if _settings.get_bool(db, KEY_ENTITIES_JOB_ENABLED, default=True)
        else "0",
        KEY_INCIDENTS_JOB_ENABLED: "1"
        if _settings.get_bool(db, KEY_INCIDENTS_JOB_ENABLED, default=True)
        else "0",
    }

    def _lu(x: LogUpload) -> Dict[str, Any]:
        return {
            "id": x.id,
            "server": x.server,
            "filename": x.filename,
            "status": x.status,
            "uploaded_at": x.uploaded_at.isoformat() if x.uploaded_at else None,
            "size_bytes": x.size_bytes,
            "error_message": (x.error_message or "")[:300],
            "meta": x.extra_meta if isinstance(x.extra_meta, dict) else {},
        }

    def _ev(x: Event) -> Dict[str, Any]:
        return {
            "id": str(x.id),
            "server": x.server,
            "source": x.source,
            "service": x.service,
            "engine_status": x.engine_status,
            "engine_attempts": int(x.engine_attempts or 0),
            "engine_claimed_at": x.engine_claimed_at.isoformat()
            if x.engine_claimed_at
            else None,
            "engine_processed_at": x.engine_processed_at.isoformat()
            if x.engine_processed_at
            else None,
            "engine_error": (x.engine_error or "")[:300],
            "created_at": x.created_at.isoformat() if x.created_at else None,
            "log_upload_id": x.log_upload_id,
        }

    payload: Dict[str, Any] = {
        "now": now.isoformat(),
        "uploads_by_status": uploads_by_status,
        "events_by_engine_status": events_by_status,  # solo cola operativa
        "alerts_24h": alerts_24h,
        "incidents_24h": incidents_24h,
        "oldest_upload_queued_at": _oldest_upload_in_status(db, "queued"),
        "oldest_event_pending_at": _oldest_pending_event(db),
        "settings": settings,
        "pending_uploads": [_lu(x) for x in pending_uploads],
        "error_uploads": [_lu(x) for x in error_uploads],
        "queue_events": [_ev(x) for x in pending_events],
    }

    _OVERVIEW_CACHE["ts"] = tnow
    _OVERVIEW_CACHE["data"] = payload
    return payload


@router.patch("/control")
def processes_control(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    payload:
      { "updates": { "pipeline.parsing.enabled": "0", ... } }
    """
    updates = payload.get("updates")
    if not isinstance(updates, dict) or not updates:
        raise HTTPException(status_code=400, detail="Missing updates dict")

    allowed = {
        KEY_PARSING_ENABLED,
        KEY_ENGINE_ENABLED,
        KEY_PARSING_MAX_PER_CYCLE,
        KEY_ENGINE_MAX_PER_CYCLE,
        KEY_PARSING_POLL_SECONDS,
        KEY_ENGINE_POLL_SECONDS,
        KEY_ENTITIES_JOB_ENABLED,
        KEY_INCIDENTS_JOB_ENABLED,
    }

    clean: Dict[str, Any] = {}
    for k, v in updates.items():
        kk = str(k or "").strip()
        if kk not in allowed:
            continue
        clean[kk] = "" if v is None else str(v)

    if not clean:
        raise HTTPException(status_code=400, detail="No allowed keys in updates")

    _settings.set_many(db, clean)
    # invalidate cache
    _OVERVIEW_CACHE["ts"] = 0.0
    _OVERVIEW_CACHE["data"] = None
    return {"ok": True, "updated": clean}


@router.post("/actions")
def processes_actions(
    payload: Dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    actions:
      - parsing_requeue_uploads: { ids:[...], delete_events: true|false }
      - parsing_requeue_errors: { limit: 50 }
      - engine_requeue_errors: { limit: 500 }
      - engine_requeue_upload: { upload_id: 123, only_errors: false }
    """
    action = str(payload.get("action") or "").strip()

    if action == "parsing_requeue_uploads":
        ids = payload.get("ids") or []
        delete_events = bool(payload.get("delete_events") or False)
        if not isinstance(ids, list) or not ids:
            raise HTTPException(status_code=400, detail="ids must be a non-empty list")

        changed = 0
        deleted_events = 0

        for raw_id in ids[:200]:
            try:
                upload_id = int(raw_id)
            except Exception:
                continue

            lu = db.query(LogUpload).filter(LogUpload.id == upload_id).first()
            if not lu:
                continue

            if delete_events:
                deleted_events += int(
                    db.query(Event)
                    .filter(Event.log_upload_id == upload_id)
                    .delete(synchronize_session=False)
                    or 0
                )

            lu.status = "queued"
            lu.error_message = None
            meta = lu.extra_meta if isinstance(lu.extra_meta, dict) else {}
            meta["ui_requeued_at"] = _utcnow().isoformat()
            meta.pop("worker_failed_at", None)
            meta.pop("worker_requeued_stale_at", None)
            meta.pop("worker_requeued_reason", None)
            lu.extra_meta = meta

            changed += 1

        db.commit()
        _OVERVIEW_CACHE["ts"] = 0.0
        _OVERVIEW_CACHE["data"] = None
        return {"ok": True, "changed": changed, "deleted_events": deleted_events}

    if action == "parsing_requeue_errors":
        limit = int(payload.get("limit") or 50)
        q = (
            db.query(LogUpload)
            .filter(LogUpload.status == "error")
            .order_by(LogUpload.uploaded_at.asc())
            .limit(max(1, min(limit, 500)))
            .all()
        )
        changed = 0
        for lu in q:
            lu.status = "queued"
            lu.error_message = None
            meta = lu.extra_meta if isinstance(lu.extra_meta, dict) else {}
            meta["ui_requeued_at"] = _utcnow().isoformat()
            lu.extra_meta = meta
            changed += 1
        db.commit()
        _OVERVIEW_CACHE["ts"] = 0.0
        _OVERVIEW_CACHE["data"] = None
        return {"ok": True, "changed": changed}

    if action == "engine_requeue_errors":
        limit = int(payload.get("limit") or 500)
        q = (
            db.query(Event)
            .filter(Event.engine_status == "error")
            .order_by(Event.created_at.asc())
            .limit(max(1, min(limit, 5000)))
            .all()
        )
        changed = 0
        for ev in q:
            ev.engine_status = "pending"
            ev.engine_claimed_at = None
            ev.engine_processed_at = None
            ev.engine_error = None
            changed += 1
        db.commit()
        _OVERVIEW_CACHE["ts"] = 0.0
        _OVERVIEW_CACHE["data"] = None
        return {"ok": True, "changed": changed}

    if action == "engine_requeue_upload":
        upload_id = payload.get("upload_id")
        only_errors = bool(payload.get("only_errors") or False)
        try:
            uid = int(upload_id)
        except Exception:
            raise HTTPException(status_code=400, detail="upload_id must be int")

        filt = [Event.log_upload_id == uid]
        if only_errors:
            filt.append(Event.engine_status == "error")

        q = db.query(Event).filter(and_(*filt)).all()
        changed = 0
        for ev in q:
            ev.engine_status = "pending"
            ev.engine_claimed_at = None
            ev.engine_processed_at = None
            ev.engine_error = None
            changed += 1

        lu = db.query(LogUpload).filter(LogUpload.id == uid).first()
        if lu and lu.status in ("processed", "processing_engine", "parsed"):
            lu.status = "parsed"
            meta = lu.extra_meta if isinstance(lu.extra_meta, dict) else {}
            meta["ui_engine_requeued_at"] = _utcnow().isoformat()
            lu.extra_meta = meta

        db.commit()
        _OVERVIEW_CACHE["ts"] = 0.0
        _OVERVIEW_CACHE["data"] = None
        return {"ok": True, "changed": changed}

    raise HTTPException(status_code=400, detail="Unknown action")

