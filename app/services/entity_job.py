# app/services/entity_job.py
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.entity import Entity
from app.models.entity_score_event import EntityScoreEvent
from app.models.service_checkpoint import ServiceCheckpoint
from app.models.system_setting import SystemSetting

CHECKPOINT_NAME = "entities_job"

# system_settings key
KEY_ENTITIES_ENABLED = "jobs.entities.enabled"

# Decay “lazy” (solo cuando tocas la entidad)
_DECAY_STEPS = [
    (timedelta(hours=24), -5),
    (timedelta(days=7), -15),
    (timedelta(days=30), -30),
]

DEFAULT_BATCH_SIZE = int(os.getenv("ENTITIES_JOB_BATCH_SIZE", "2000"))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_dt(s: str) -> datetime:
    # Acepta ISO8601, con o sin Z
    s = (s or "").strip()
    if not s:
        raise ValueError("empty datetime")
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return _utc(dt) or dt.replace(tzinfo=timezone.utc)


def _severity_from_score(score: int) -> str:
    if score <= 9:
        return "clean"
    if score <= 29:
        return "low"
    if score <= 59:
        return "medium"
    if score <= 79:
        return "high"
    return "critical"


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def _get_bool_setting(db: Session, key: str, default: bool = True) -> bool:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not row:
        return bool(default)
    raw = (row.value or "").strip().lower()
    if raw == "":
        return bool(default)
    return raw in ("1", "true", "yes", "y", "on", "enabled")


def _extract_group_values(alert: Alert) -> Dict[str, Any]:
    ev = alert.evidence or {}
    if isinstance(ev, dict):
        gv = ev.get("group_values")
        if isinstance(gv, dict):
            return gv
    return {}


def _extract_entity_attrs_from_alert(alert: Alert) -> Dict[str, Any]:
    """
    Copia datos útiles para UI hacia Entity.attrs.
    Soporta:
      - evidence.group_values: "extra.geo.country_code", "extra.asn.number"
      - evidence.geo / evidence.asn
      - evidence.enrich.geo / evidence.enrich.asn
    """
    ev = alert.evidence or {}
    if not isinstance(ev, dict):
        ev = {}

    gv = _extract_group_values(alert)

    def _pick(*keys: str) -> Optional[Any]:
        for k in keys:
            v = gv.get(k)
            if v is not None and _as_str(v).strip() != "":
                return v
        return None

    attrs: Dict[str, Any] = {}

    cc = _pick("extra.geo.country_code", "geo.country_code", "country_code")
    asn_num = _pick("extra.asn.number", "asn.number", "asn")

    if cc:
        attrs.setdefault("geo", {})
        attrs["geo"]["country_code"] = _as_str(cc).strip().upper()

    if asn_num:
        attrs.setdefault("asn", {})
        try:
            attrs["asn"]["number"] = int(asn_num)
        except Exception:
            attrs["asn"]["number"] = _as_str(asn_num).strip()

    geo = ev.get("geo")
    if isinstance(geo, dict):
        attrs.setdefault("geo", {})
        attrs["geo"] = {**attrs["geo"], **geo}

    asn = ev.get("asn")
    if isinstance(asn, dict):
        attrs.setdefault("asn", {})
        attrs["asn"] = {**attrs["asn"], **asn}

    enrich = ev.get("enrich")
    if isinstance(enrich, dict):
        egeo = enrich.get("geo")
        if isinstance(egeo, dict):
            attrs.setdefault("geo", {})
            attrs["geo"] = {**attrs["geo"], **egeo}

        easn = enrich.get("asn")
        if isinstance(easn, dict):
            attrs.setdefault("asn", {})
            attrs["asn"] = {**attrs["asn"], **easn}

    return attrs


def _merge_attrs(existing: Any, incoming: Dict[str, Any]) -> Dict[str, Any]:
    cur: Dict[str, Any] = existing if isinstance(existing, dict) else {}
    for k, v in incoming.items():
        if isinstance(v, dict):
            cur_section = cur.get(k)
            if not isinstance(cur_section, dict):
                cur_section = {}
            cur[k] = {**cur_section, **v}
        else:
            cur[k] = v
    return cur


def _pick_primary_entity(alert: Alert) -> Optional[Tuple[str, str, str]]:
    """
    Heurística simple:
    Prioriza username/ip_client/ip_subnet24/extra.vhost/extra.asn.number/extra.geo.country_code
    Retorna (entity_type, entity_key, scope_guess)
    """
    gv = _extract_group_values(alert)
    scope = "local"

    if _as_str(gv.get("username")).strip():
        return ("user", _as_str(gv.get("username")).strip().lower(), scope)
    if _as_str(gv.get("ip_client")).strip():
        return ("ip", _as_str(gv.get("ip_client")).strip(), scope)
    if _as_str(gv.get("ip_subnet24")).strip():
        return ("subnet24", _as_str(gv.get("ip_subnet24")).strip(), scope)
    if _as_str(gv.get("extra.vhost")).strip():
        return ("host", _as_str(gv.get("extra.vhost")).strip().lower(), scope)
    if _as_str(gv.get("extra.asn.number")).strip():
        return ("asn", _as_str(gv.get("extra.asn.number")).strip(), "global")
    if _as_str(gv.get("extra.geo.country_code")).strip():
        return ("country", _as_str(gv.get("extra.geo.country_code")).strip().upper(), "global")
    if _as_str(gv.get("server")).strip():
        return ("server", _as_str(gv.get("server")).strip(), "local")

    return None


def _apply_decay_if_needed(entity: Entity, now: datetime) -> int:
    last_upd = _utc(entity.score_updated_at) or _utc(entity.last_seen_at)
    if not last_upd:
        return 0

    age = now - last_upd
    delta = 0
    for threshold, d in _DECAY_STEPS:
        if age >= threshold:
            delta = d

    if delta == 0:
        return 0

    new_score = max(0, min(100, int(entity.score_current or 0) + delta))
    entity.score_current = new_score
    entity.severity = _severity_from_score(new_score)
    entity.score_updated_at = now
    return delta


def _get_or_create_checkpoint(db: Session) -> ServiceCheckpoint:
    cp = db.query(ServiceCheckpoint).filter(ServiceCheckpoint.name == CHECKPOINT_NAME).first()
    if not cp:
        cp = ServiceCheckpoint(name=CHECKPOINT_NAME, meta={})
        db.add(cp)
        db.flush()
    if not isinstance(cp.meta, dict):
        cp.meta = {}
    return cp


def run_entities_job(
    db: Session,
    *,
    now: Optional[datetime] = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    from_alert_id: Optional[int] = None,
    from_triggered_at: Optional[datetime] = None,
    dry_run: bool = False,
    max_batches: Optional[int] = None,
) -> int:
    """
    Consume alertas incrementalmente por ID (checkpoint meta.last_alert_id).

    Backfill:
      - from_alert_id: procesa alerts.id > from_alert_id
      - from_triggered_at: encuentra el primer id cuya triggered_at >= from_triggered_at y procesa desde ahí

    Retorna #alerts “tocadas” (que resultaron en delta != 0 o decay ledger).
    """
    now = _utc(now) or _utcnow()
    cp = _get_or_create_checkpoint(db)

    enabled = _get_bool_setting(db, KEY_ENTITIES_ENABLED, default=True)
    if not enabled:
        if not dry_run:
            meta = dict(cp.meta) if isinstance(cp.meta, dict) else {}
            meta["mode"] = "realtime"
            meta["skipped_reason"] = "disabled_via_system_settings"
            meta["skipped_at"] = now.isoformat()
            cp.meta = dict(meta)
            cp.last_run_at = now
            db.add(cp)
            db.commit()
        print("[entities_job] disabled via system_settings (jobs.entities.enabled=0)")
        return 0

    meta = dict(cp.meta) if isinstance(cp.meta, dict) else {}
    last_id_meta = int(meta.get("last_alert_id") or 0)

    start_id = last_id_meta
    mode = "realtime"

    if from_triggered_at is not None:
        mode = "backfill"
        first = (
            db.query(Alert.id)
            .filter(Alert.triggered_at >= _utc(from_triggered_at))
            .order_by(Alert.id.asc())
            .first()
        )
        start_id = int(first[0]) - 1 if first else start_id
    if from_alert_id is not None:
        mode = "backfill"
        start_id = int(from_alert_id)

    meta["mode"] = mode
    if mode == "backfill":
        meta.setdefault("backfill_started_at", now.isoformat())

    touched = 0
    batches = 0
    processed_last_id = start_id

    while True:
        q = (
            db.query(Alert)
            .filter(Alert.id > processed_last_id)
            .order_by(Alert.id.asc())
            .limit(batch_size)
        )

        alerts = q.all()
        if not alerts:
            break

        batches += 1
        if max_batches is not None and batches > max_batches:
            break

        for al in alerts:
            processed_last_id = int(al.id)

            picked = _pick_primary_entity(al)
            if not picked:
                continue

            etype, ekey, scope = picked
            ts = _utc(al.triggered_at) or now

            new_attrs = _extract_entity_attrs_from_alert(al)

            ent = (
                db.query(Entity)
                .filter(Entity.entity_type == etype, Entity.entity_key == ekey)
                .first()
            )
            if not ent:
                ent = Entity(
                    entity_type=etype,
                    entity_key=ekey,
                    scope=scope,
                    score_current=0,
                    severity="clean",
                    first_seen_at=ts,
                    last_seen_at=ts,
                    score_updated_at=ts,
                    attrs=new_attrs or {},
                )
                db.add(ent)
                db.flush()
            else:
                if new_attrs:
                    ent.attrs = _merge_attrs(ent.attrs, new_attrs)

            decay_delta = _apply_decay_if_needed(ent, now)
            if decay_delta != 0:
                db.add(
                    EntityScoreEvent(
                        entity_id=ent.id,
                        ts=now,
                        delta=decay_delta,
                        reason_type="decay",
                        reason_id=None,
                        meta={"policy": "lazy_decay"},
                    )
                )
                touched += 1

            try:
                delta = int(al.severity or 0)
            except Exception:
                delta = 0
            if delta == 0:
                continue

            cur = int(ent.score_current or 0)
            new_score = max(0, min(100, cur + delta))

            ent.score_current = new_score
            ent.severity = _severity_from_score(new_score)
            ent.last_seen_at = max(_utc(ent.last_seen_at) or ts, ts)
            ent.score_updated_at = now

            db.add(
                EntityScoreEvent(
                    entity_id=ent.id,
                    ts=ts,
                    delta=delta,
                    reason_type="alert",
                    reason_id=str(al.id),
                    meta={
                        "alert_rule_name": al.rule_name,
                        "server": al.server,
                        "source": al.source,
                        "event_type": al.event_type,
                        "group_key": al.group_key,
                    },
                )
            )

            touched += 1

        # avance de checkpoint (CRÍTICO)
        meta["last_alert_id"] = processed_last_id
        meta["last_batch_at"] = now.isoformat()
        cp.meta = dict(meta)
        cp.last_run_at = now
        db.add(cp)

        if dry_run:
            db.rollback()
        else:
            db.commit()

        # si hicimos rollback, recargamos meta para no seguir con valores locales
        if dry_run:
            meta = dict(cp.meta) if isinstance(cp.meta, dict) else {}

    if mode == "backfill" and not dry_run:
        meta["backfill_completed_at"] = now.isoformat()
        meta["last_alert_id"] = processed_last_id
        cp.meta = dict(meta)
        cp.last_run_at = now
        db.add(cp)
        db.commit()

    return touched


def _get_db_session() -> Session:
    from app.db import SessionLocal  # type: ignore
    return SessionLocal()


def main() -> None:
    p = argparse.ArgumentParser(description="SentinelX Entities Job (incremental by alert.id, supports backfill)")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    p.add_argument("--from-alert-id", type=int, default=None, help="Backfill: start after this alert id (alerts.id > X)")
    p.add_argument("--from-triggered-at", type=str, default=None, help="Backfill: ISO datetime, start from alerts.triggered_at >= this")
    p.add_argument("--max-batches", type=int, default=None, help="Limit batches for safety/testing")
    p.add_argument("--dry-run", action="store_true", help="Do not commit, rollback changes")
    args = p.parse_args()

    from_ts = _parse_dt(args.from_triggered_at) if args.from_triggered_at else None

    db = _get_db_session()
    try:
        touched = run_entities_job(
            db,
            batch_size=args.batch_size,
            from_alert_id=args.from_alert_id,
            from_triggered_at=from_ts,
            dry_run=args.dry_run,
            max_batches=args.max_batches,
        )

        if args.dry_run:
            print(f"[entities_job] DRY_RUN touched={touched} (rollback)")
        else:
            print(f"[entities_job] touched={touched}")

    except Exception as e:
        db.rollback()
        print(f"[entities_job] ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()

