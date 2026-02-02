from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.event import Event
from app.models.rule_state_v2 import RuleStateV2
from app.models.rule_v2 import RuleV2
from app.services.rule_engine_v2 import RuleEngineV2


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def reprocess_events(
    db: Session,
    *,
    time_min: datetime,
    time_max: datetime,
    rule_id: Optional[int] = None,
    server: Optional[str] = None,
    max_events: int = 200_000,
) -> dict:
    """
    Reprocesa recreando Alerts + RuleStateV2 para un rango [time_min, time_max].
    Estrategia segura:
      1) borrar alerts del rango (y rule_id si aplica)
      2) borrar states de la(s) regla(s) (y opcionalmente solo del server si tu group_key incluye server)
      3) iterar events ordenados y correr engine.on_event()
    """
    tmin = _utc(time_min)
    tmax = _utc(time_max)

    # --- Selección de reglas ---
    q_rules = db.query(RuleV2).filter(RuleV2.enabled.is_(True))
    if rule_id is not None:
        q_rules = q_rules.filter(RuleV2.id == rule_id)

    rules = q_rules.all()
    if not rules:
        return {"ok": True, "rules": 0, "events_scanned": 0, "alerts_created": 0, "note": "no rules"}

    rule_ids = [r.id for r in rules]

    # --- Borrar alerts existentes en ese rango (para reconstruir) ---
    q_del_alerts = db.query(Alert).filter(Alert.triggered_at >= tmin, Alert.triggered_at <= tmax)
    q_del_alerts = q_del_alerts.filter(Alert.rule_id.in_(rule_ids))
    if server:
        q_del_alerts = q_del_alerts.filter(Alert.server == server)
    deleted_alerts = q_del_alerts.delete(synchronize_session=False)

    # --- Borrar estados de cooldown para reglas (reconstrucción consistente) ---
    # Nota: si tu group_key incluye server, podrías filtrar states por group_key LIKE f"{server}|%"
    # pero eso depende de tu group_by. Por seguridad, se limpian completos para esa(s) regla(s).
    deleted_states = (
        db.query(RuleStateV2)
        .filter(RuleStateV2.rule_id.in_(rule_ids))
        .delete(synchronize_session=False)
    )

    db.flush()

    # --- Engine batch fresh (NO usar singleton: evita contaminar ventanas in-memory del runtime) ---
    engine = RuleEngineV2()
    # Index solo con estas reglas para hacerlo eficiente
    idx = {}
    for r in rules:
        src = (r.source or "").strip().upper()
        et = (r.event_type or "").strip().lower()
        idx.setdefault((src, et), []).append(r)
    engine._index = idx  # intencional (batch mode)
    engine._windows.clear()

    # --- Iterar eventos ordenados ---
    q_events = db.query(Event).filter(Event.timestamp_utc >= tmin, Event.timestamp_utc <= tmax)
    if server:
        q_events = q_events.filter(Event.server == server)

    q_events = q_events.order_by(Event.timestamp_utc.asc())

    scanned = 0
    alerts_created = 0

    # yield_per para no cargar todo en RAM
    for ev in q_events.yield_per(1000):
        scanned += 1
        if scanned > max_events:
            break

        # engine.on_event agrega Alert/State al db
        alerts = engine.on_event(db, ev)
        alerts_created += len(alerts)

        if scanned % 2000 == 0:
            db.flush()

    db.commit()

    return {
        "ok": True,
        "rules": len(rules),
        "events_scanned": scanned,
        "alerts_deleted": int(deleted_alerts or 0),
        "states_deleted": int(deleted_states or 0),
        "alerts_created": int(alerts_created),
        "time_min": tmin.isoformat(),
        "time_max": tmax.isoformat(),
        "server": server,
        "rule_id": rule_id,
        "truncated": scanned >= max_events,
        "max_events": max_events,
    }
