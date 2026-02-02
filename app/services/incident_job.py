# app/services/incident_job.py
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.service_checkpoint import ServiceCheckpoint
from app.models.system_setting import SystemSetting
from app.services.incident_engine import IncidentEngine

CHECKPOINT_NAME = "incidents_job"

# system_settings key
KEY_INCIDENTS_ENABLED = "jobs.incidents.enabled"


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(s: str) -> datetime:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty datetime")
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return _utc(dt) or dt.replace(tzinfo=timezone.utc)


def _get_or_create_checkpoint(db: Session) -> ServiceCheckpoint:
    cp = db.query(ServiceCheckpoint).filter(ServiceCheckpoint.name == CHECKPOINT_NAME).first()
    if not cp:
        cp = ServiceCheckpoint(name=CHECKPOINT_NAME, meta={})
        db.add(cp)
        db.flush()
    if not isinstance(cp.meta, dict):
        cp.meta = {}
    return cp


def _get_bool_setting(db: Session, key: str, default: bool = True) -> bool:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not row:
        return bool(default)
    raw = (row.value or "").strip().lower()
    if raw == "":
        return bool(default)
    return raw in ("1", "true", "yes", "y", "on", "enabled")


def run_incidents_job(
    db: Session,
    *,
    now: Optional[datetime] = None,
    dry_run: bool = False,
) -> int:
    """
    Realtime: corre el engine con now y genera/actualiza incidentes.
    """
    now = _utc(now) or _utcnow()

    # control-plane: permitir pausar el job sin tocar cron
    enabled = _get_bool_setting(db, KEY_INCIDENTS_ENABLED, default=True)
    if not enabled:
        if not dry_run:
            cp = _get_or_create_checkpoint(db)
            meta = cp.meta if isinstance(cp.meta, dict) else {}
            meta["mode"] = "realtime"
            meta["skipped_reason"] = "disabled_via_system_settings"
            meta["skipped_at"] = now.isoformat()
            cp.meta = meta
            cp.last_run_at = now
            db.add(cp)
            db.commit()
        print("[incidents_job] disabled via system_settings (jobs.incidents.enabled=0)")
        return 0

    engine = IncidentEngine()
    engine.reload_rules(db)
    incidents = engine.run(db, now=now)

    if dry_run:
        return len(incidents)

    cp = _get_or_create_checkpoint(db)
    meta = cp.meta if isinstance(cp.meta, dict) else {}
    meta["mode"] = "realtime"
    meta["last_run_now"] = now.isoformat()
    cp.meta = meta
    cp.last_run_at = now
    db.add(cp)
    db.commit()
    return len(incidents)


def run_incidents_backfill(
    db: Session,
    *,
    from_ts: datetime,
    to_ts: datetime,
    step_seconds: int = 300,
    dry_run: bool = False,
) -> int:
    """
    Backfill “pro”: ejecuta el engine en slices de tiempo:
      now = from_ts, from_ts+step, ... hasta to_ts

    Esto genera incidentes históricos respetando ventanas/cooldowns.
    """
    from_ts = _utc(from_ts) or from_ts
    to_ts = _utc(to_ts) or to_ts

    if to_ts <= from_ts:
        return 0

    # control-plane: permitir pausar el backfill también
    enabled = _get_bool_setting(db, KEY_INCIDENTS_ENABLED, default=True)
    if not enabled:
        if not dry_run:
            cp = _get_or_create_checkpoint(db)
            meta = cp.meta if isinstance(cp.meta, dict) else {}
            meta["mode"] = "backfill"
            meta["skipped_reason"] = "disabled_via_system_settings"
            meta["skipped_at"] = _utcnow().isoformat()
            meta["backfill_from"] = from_ts.isoformat()
            meta["backfill_to"] = to_ts.isoformat()
            meta["step_seconds"] = int(step_seconds)
            cp.meta = meta
            cp.last_run_at = _utcnow()
            db.add(cp)
            db.commit()
        print("[incidents_job] backfill disabled via system_settings (jobs.incidents.enabled=0)")
        return 0

    engine = IncidentEngine()
    engine.reload_rules(db)

    total = 0
    cur = from_ts

    if not dry_run:
        cp = _get_or_create_checkpoint(db)
        meta = cp.meta if isinstance(cp.meta, dict) else {}
        meta["mode"] = "backfill"
        meta["backfill_started_at"] = _utcnow().isoformat()
        meta["backfill_from"] = from_ts.isoformat()
        meta["backfill_to"] = to_ts.isoformat()
        meta["step_seconds"] = int(step_seconds)
        cp.meta = meta
        db.add(cp)
        db.commit()

    while cur <= to_ts:
        incidents = engine.run(db, now=cur)
        total += len(incidents)

        if dry_run:
            db.rollback()
        else:
            cp = _get_or_create_checkpoint(db)
            meta = cp.meta if isinstance(cp.meta, dict) else {}
            meta["backfill_cursor"] = cur.isoformat()
            cp.meta = meta
            cp.last_run_at = cur
            db.add(cp)
            db.commit()

        cur = cur + timedelta(seconds=int(step_seconds))

    if not dry_run:
        cp = _get_or_create_checkpoint(db)
        meta = cp.meta if isinstance(cp.meta, dict) else {}
        meta["backfill_completed_at"] = _utcnow().isoformat()
        cp.meta = meta
        cp.last_run_at = to_ts
        db.add(cp)
        db.commit()

    return total


def _get_db_session() -> Session:
    from app.db import SessionLocal  # type: ignore
    return SessionLocal()


def main() -> None:
    p = argparse.ArgumentParser(description="SentinelX Incidents Job (realtime + optional backfill time-slicing)")
    p.add_argument("--dry-run", action="store_true", help="Do not commit, rollback changes")

    # Backfill options
    p.add_argument("--backfill-from", type=str, default=None, help="ISO datetime start (UTC recommended)")
    p.add_argument("--backfill-to", type=str, default=None, help="ISO datetime end (UTC recommended)")
    p.add_argument("--step-seconds", type=int, default=300, help="Backfill step size (default 300s)")

    args = p.parse_args()

    db = _get_db_session()
    try:
        if args.backfill_from and args.backfill_to:
            n = run_incidents_backfill(
                db,
                from_ts=_parse_dt(args.backfill_from),
                to_ts=_parse_dt(args.backfill_to),
                step_seconds=int(args.step_seconds),
                dry_run=args.dry_run,
            )
            if args.dry_run:
                print(f"[incidents_job] DRY_RUN backfill incidents={n} (rollback)")
            else:
                print(f"[incidents_job] backfill incidents={n}")
        else:
            n = run_incidents_job(db, dry_run=args.dry_run)
            if args.dry_run:
                print(f"[incidents_job] DRY_RUN incidents={n} (rollback)")
            else:
                print(f"[incidents_job] incidents={n}")

    except Exception as e:
        db.rollback()
        print(f"[incidents_job] ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
