# app/router/dashboard.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

from app.db import get_db
from app.routers.auth import get_current_user
from app.models.user import User

from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.incident_entity import IncidentEntity
from app.models.entity import Entity
from app.models.log_upload import LogUpload

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ----------------------------
# Helpers
# ----------------------------

def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    s = dt_str.strip()
    if not s:
        return None
    try:
        if len(s) == 10 and s[4] == "-" and s[7] == "-":
            return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        return _utc(datetime.fromisoformat(s.replace("Z", "+00:00")))
    except Exception:
        return None


def _time_range(
    *,
    days: Optional[int],
    from_str: Optional[str],
    to_str: Optional[str],
) -> Tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)

    dt_from = _parse_iso(from_str)
    dt_to = _parse_iso(to_str)

    if dt_from and dt_to:
        if to_str and len(to_str.strip()) == 10:
            dt_to = dt_to + timedelta(days=1) - timedelta(seconds=1)
        return dt_from, dt_to

    d = int(days or 7)
    if d <= 0:
        d = 7
    start = now - timedelta(days=d)
    return start, now


def _severity_filter_to_min(sev: Optional[str]) -> Optional[int]:
    """
    Mapping UI -> min severity para alerts (ajusta si quieres):
      - high   => >= 10
      - medium => >= 6
      - low    => >= 1
      - all    => None
    """
    s = (sev or "").strip().lower()
    if s == "high":
        return 10
    if s == "medium":
        return 6
    if s == "low":
        return 1
    return None


def _incident_active_statuses() -> Tuple[str, ...]:
    return ("open", "triage", "contained")


def _incident_level(sev: int) -> str:
    # Normaliza a {low, medium, high} para UI
    if sev >= 85:
        return "high"
    if sev >= 60:
        return "medium"
    return "low"


def _status_code_by_lag(lag_seconds: Optional[int], *, warn: int, crit: int) -> str:
    """
    Return: ok | warning | error | unknown
    """
    if lag_seconds is None:
        return "unknown"
    if lag_seconds >= crit:
        return "error"
    if lag_seconds >= warn:
        return "warning"
    return "ok"


def _lag_seconds_from(ts: Optional[datetime]) -> Optional[int]:
    if not ts:
        return None
    now = datetime.now(timezone.utc)
    t = _utc(ts)
    if not t:
        return None
    return int((now - t).total_seconds())


# ----------------------------
# KPIs
# ----------------------------

@router.get("/kpis")
def dashboard_kpis(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    server: Optional[str] = Query(default=None),
    days: Optional[int] = Query(default=7, ge=1, le=365),
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default="all"),
) -> Dict[str, Any]:
    start, end = _time_range(days=days, from_str=from_, to_str=to)

    # Alerts en rango
    q_alert = db.query(Alert).filter(Alert.triggered_at >= start, Alert.triggered_at <= end)
    if server and server != "all":
        q_alert = q_alert.filter(Alert.server == server)

    min_sev = _severity_filter_to_min(severity)
    if min_sev is not None:
        q_alert = q_alert.filter(Alert.severity >= min_sev)

    alerts_total = q_alert.count()
    alerts_open = q_alert.filter(Alert.status == "open").count()

    # "high/critical": usamos >= 15 como “fuerte” (ajustable)
    alerts_high_critical = q_alert.filter(Alert.severity >= 15).count()

    # Incidents (estado actual)
    q_inc = db.query(Incident).filter(Incident.status.in_(_incident_active_statuses()))
    if server and server != "all":
        q_inc = q_inc.filter(Incident.server == server)

    incidents_active = q_inc.count()
    incidents_critical = q_inc.filter(Incident.severity_current >= 90).count()

    # Entities (solo relacionadas a incidentes activos)
    active_statuses = _incident_active_statuses()

    q_ent_risky = (
        db.query(func.count(distinct(Entity.id)))
        .select_from(Incident)
        .join(IncidentEntity, IncidentEntity.incident_id == Incident.id)
        .join(Entity, Entity.id == IncidentEntity.entity_id)
        .filter(Incident.status.in_(active_statuses))
        .filter(Entity.score_current >= 30)
    )

    q_ent_critical = (
        db.query(func.count(distinct(Entity.id)))
        .select_from(Incident)
        .join(IncidentEntity, IncidentEntity.incident_id == Incident.id)
        .join(Entity, Entity.id == IncidentEntity.entity_id)
        .filter(Incident.status.in_(active_statuses))
        .filter(Entity.score_current >= 80)
    )

    if server and server != "all":
        q_ent_risky = q_ent_risky.filter(Incident.server == server)
        q_ent_critical = q_ent_critical.filter(Incident.server == server)

    entities_risky = int(q_ent_risky.scalar() or 0)
    entities_critical = int(q_ent_critical.scalar() or 0)

    # Events / Sources (en rango)
    q_ev = db.query(Event).filter(Event.timestamp_utc >= start, Event.timestamp_utc <= end)
    if server and server != "all":
        q_ev = q_ev.filter(Event.server == server)

    events_count = q_ev.count()
    active_sources = (
        db.query(func.count(distinct(Event.source)))
        .filter(Event.timestamp_utc >= start, Event.timestamp_utc <= end)
    )
    if server and server != "all":
        active_sources = active_sources.filter(Event.server == server)
    active_sources_n = int(active_sources.scalar() or 0)

    # Uploads
    uploads_24h_start = datetime.now(timezone.utc) - timedelta(hours=24)
    q_up = db.query(LogUpload).filter(LogUpload.uploaded_at >= uploads_24h_start)
    if server and server != "all":
        q_up = q_up.filter(LogUpload.server == server)
    uploads_24h = q_up.count()
    uploads_failed_24h = q_up.filter(LogUpload.status.in_(["failed", "error"])).count()

    # Health-ish timestamps
    last_event_at = (
        db.query(func.max(Event.timestamp_utc))
        .filter(*( [Event.server == server] if (server and server != "all") else [] ))
        .scalar()
    )
    last_alert_at = (
        db.query(func.max(Alert.triggered_at))
        .filter(*( [Alert.server == server] if (server and server != "all") else [] ))
        .scalar()
    )
    last_incident_at = (
        db.query(func.max(Incident.last_activity_at))
        .filter(*( [Incident.server == server] if (server and server != "all") else [] ))
        .scalar()
    )

    return {
        "range": {
            "from": start.isoformat(),
            "to": end.isoformat(),
            "server": server or "all",
            "severity": severity or "all",
        },
        "alerts": {
            "total": alerts_total,
            "open": alerts_open,
            "high_critical": alerts_high_critical,
        },
        "incidents": {
            "active": incidents_active,
            "critical": incidents_critical,
        },
        "entities": {
            "risky": entities_risky,
            "critical": entities_critical,
        },
        "ingest": {
            "events": events_count,
            "active_sources": active_sources_n,
            "uploads_24h": uploads_24h,
            "uploads_failed_24h": uploads_failed_24h,
        },
        "health": {
            "db": "ok",
            "last_event_at": _utc(last_event_at).isoformat() if last_event_at else None,
            "last_alert_at": _utc(last_alert_at).isoformat() if last_alert_at else None,
            "last_incident_at": _utc(last_incident_at).isoformat() if last_incident_at else None,
            "lag_seconds": _lag_seconds_from(last_event_at),
        },
    }


# ----------------------------
# Activity (para ActivityChart)
# ----------------------------

@router.get("/activity")
def dashboard_activity(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    server: Optional[str] = Query(default=None),
    days: Optional[int] = Query(default=7, ge=1, le=90),
    from_: Optional[str] = Query(default=None, alias="from"),
    to: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """
    Serie diaria basada en ALERTAS (v2).
    Mapea categorías usando el prefijo del "code" dentro de Alert.rule_name:
      - bruteForce: AUTH-*
      - bots: WEB-001/WEB-002/WEB-004/WEB-007 (recon/bots/keywords)
      - exploits: WEB-003
      - wpCoreErrors: WEB-005
      - fileAnomalies: FILE-*
      - mailThreats: MAIL-*
      - panelAccess: AUTH-005 (si lo usas) / PANEL-* (si lo creas luego)
    """
    start, end = _time_range(days=days, from_str=from_, to_str=to)

    q = db.query(Alert).filter(Alert.triggered_at >= start, Alert.triggered_at <= end)
    if server and server != "all":
        q = q.filter(Alert.server == server)

    # extrae "CODE" del rule_name: toma el primer token
    # en PG: split_part(rule_name, ' ', 1)
    code_expr = func.split_part(Alert.rule_name, " ", 1)

    day_expr = func.date_trunc("day", Alert.triggered_at)

    bots_codes = ["WEB-001", "WEB-002", "WEB-004", "WEB-007"]
    exploit_codes = ["WEB-003"]
    wp_codes = ["WEB-005"]

    # sums
    rows = (
        db.query(
            day_expr.label("day"),
            func.count(Alert.id).label("total"),
            func.sum(case((code_expr.like("AUTH-%"), 1), else_=0)).label("bruteforce"),
            func.sum(case((code_expr.in_(bots_codes), 1), else_=0)).label("bots"),
            func.sum(case((code_expr.in_(exploit_codes), 1), else_=0)).label("exploits"),
            func.sum(case((code_expr.in_(wp_codes), 1), else_=0)).label("wp"),
            func.sum(case((code_expr.like("FILE-%"), 1), else_=0)).label("file"),
            func.sum(case((code_expr.like("MAIL-%"), 1), else_=0)).label("mail"),
            func.sum(case((code_expr.in_(["AUTH-005"]), 1), else_=0)).label("panel"),
        )
        .filter(Alert.triggered_at >= start, Alert.triggered_at <= end)
        .filter(*( [Alert.server == server] if (server and server != "all") else [] ))
        .group_by(day_expr)
        .order_by(day_expr.asc())
        .all()
    )

    # Construye serie con huecos (para que la gráfica no “salte”)
    series: List[Dict[str, Any]] = []
    cur = start.replace(hour=0, minute=0, second=0, microsecond=0)
    end_day = end.replace(hour=0, minute=0, second=0, microsecond=0)

    # índice por día
    by_day: Dict[str, Any] = {}
    for r in rows:
        d = _utc(r.day) or r.day
        key = d.date().isoformat()
        by_day[key] = r

    while cur <= end_day:
        key = cur.date().isoformat()
        r = by_day.get(key)

        # label corta: "MM-DD" (la UI ya lo usa)
        label = f"{cur.month:02d}-{cur.day:02d}"

        series.append(
            {
                "date": key,
                "label": label,
                "bruteForce": int(getattr(r, "bruteforce", 0) or 0) if r else 0,
                "bots": int(getattr(r, "bots", 0) or 0) if r else 0,
                "exploits": int(getattr(r, "exploits", 0) or 0) if r else 0,
                "wpCoreErrors": int(getattr(r, "wp", 0) or 0) if r else 0,
                "fileAnomalies": int(getattr(r, "file", 0) or 0) if r else 0,
                "mailThreats": int(getattr(r, "mail", 0) or 0) if r else 0,
                "panelAccess": int(getattr(r, "panel", 0) or 0) if r else 0,
            }
        )
        cur = cur + timedelta(days=1)

    return {
        "range": {"from": start.isoformat(), "to": end.isoformat(), "server": server or "all"},
        "series": series,
    }


# ----------------------------
# Recent incidents normalized (para RecentEventsCard)
# ----------------------------

@router.get("/incidents/recent")
def dashboard_recent_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    server: Optional[str] = Query(default=None),
    days: Optional[int] = Query(default=7, ge=1, le=90),
    status: Optional[str] = Query(default="open"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10000),
) -> Dict[str, Any]:
    """
    Devuelve items con la forma que tu card ya espera:
      - level, severityLabel, type, description, ip, server, datetime
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=int(days or 7))

    q = db.query(Incident).filter(Incident.last_activity_at >= start)

    if status and status != "all":
        q = q.filter(Incident.status == status)

    if server and server != "all":
        q = q.filter(Incident.server == server)

    q = q.order_by(Incident.last_activity_at.desc())

    items_db = q.offset(offset).limit(limit).all()

    items: List[Dict[str, Any]] = []
    for inc in items_db:
        sev = int(inc.severity_current or inc.severity_base or 0)
        lvl = _incident_level(sev)
        sev_label = "Alta" if lvl == "high" else "Media" if lvl == "medium" else "Baja"

        # “ip” en tu tabla realmente es "entidad principal"; si no es ip, igual se muestra ahí.
        primary = (inc.primary_entity_key or "—")
        srv = inc.server or "—"

        items.append(
            {
                "level": lvl,
                "severityLabel": sev_label,
                "type": f"{inc.code} · {inc.name}",
                "description": inc.resolution_note or "",
                "ip": primary,
                "server": srv,
                "datetime": _utc(inc.last_activity_at).isoformat() if inc.last_activity_at else None,
            }
        )

    return {"items": items, "limit": limit, "offset": offset}


# ----------------------------
# Entities top (reemplazo de "IPs sospechosas")
# ----------------------------

@router.get("/entities/top")
def dashboard_top_entities(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    entity_type: str = Query(default="ip"),
    limit: int = Query(default=4, ge=1, le=50),
) -> Dict[str, Any]:
    """
    Top entidades por score_current. En v2 es mejor que "ips/top".
    """
    q = (
        db.query(Entity)
        .filter(Entity.entity_type == entity_type)
        .order_by(Entity.score_current.desc(), Entity.updated_at.desc())
        .limit(limit)
    )

    out: List[Dict[str, Any]] = []
    for e in q.all():
        out.append(
            {
                "entity_type": e.entity_type,
                "entity_key": e.entity_key,
                "score": int(e.score_current or 0),
                "severity": e.severity,
                "last_seen_at": _utc(e.last_seen_at).isoformat() if e.last_seen_at else None,
            }
        )

    return {"items": out}


# ----------------------------
# System status (para SystemStatusCard)
# ----------------------------

@router.get("/system-status")
def dashboard_system_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Estado del sistema v2:
      - Ingesta (lag por último Event)
      - Correlación/Alertas (lag por última Alert)
      - Incidentes (lag por último Incident activity)
      - Uploads fallidos en 24h
    """
    now = datetime.now(timezone.utc)

    last_event_at = db.query(func.max(Event.timestamp_utc)).scalar()
    last_alert_at = db.query(func.max(Alert.triggered_at)).scalar()
    last_incident_at = db.query(func.max(Incident.last_activity_at)).scalar()

    lag_events = _lag_seconds_from(last_event_at)
    lag_alerts = _lag_seconds_from(last_alert_at)
    lag_inc = _lag_seconds_from(last_incident_at)

    # uploads 24h
    up_start = now - timedelta(hours=24)
    uploads_24h = db.query(LogUpload).filter(LogUpload.uploaded_at >= up_start).count()
    uploads_failed_24h = (
        db.query(LogUpload)
        .filter(LogUpload.uploaded_at >= up_start, LogUpload.status.in_(["failed", "error"]))
        .count()
    )

    # thresholds (ajustables)
    ingest_code = _status_code_by_lag(lag_events, warn=900, crit=3600)
    alerts_code = _status_code_by_lag(lag_alerts, warn=900, crit=3600)
    inc_code = _status_code_by_lag(lag_inc, warn=3600, crit=21600)  # incidentes pueden ser más lentos

    uploads_code = "ok"
    if uploads_failed_24h >= 10:
        uploads_code = "error"
    elif uploads_failed_24h > 0:
        uploads_code = "warning"

    def fmt_secs(s: Optional[int]) -> str:
        if s is None:
            return "—"
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s//60}m"
        return f"{s//3600}h"

    items = [
        {
            "component": "Ingesta (events)",
            "status": "OK" if ingest_code == "ok" else "Atención" if ingest_code == "warning" else "Crítico" if ingest_code == "error" else "Sin datos",
            "detail": f"Último evento: {(_utc(last_event_at).isoformat() if last_event_at else '—')} · lag {fmt_secs(lag_events)}",
            "status_code": ingest_code,
        },
        {
            "component": "Correlación (alerts)",
            "status": "OK" if alerts_code == "ok" else "Atención" if alerts_code == "warning" else "Crítico" if alerts_code == "error" else "Sin datos",
            "detail": f"Última alerta: {(_utc(last_alert_at).isoformat() if last_alert_at else '—')} · lag {fmt_secs(lag_alerts)}",
            "status_code": alerts_code,
        },
        {
            "component": "Incidentes",
            "status": "OK" if inc_code == "ok" else "Atención" if inc_code == "warning" else "Crítico" if inc_code == "error" else "Sin datos",
            "detail": f"Última actividad: {(_utc(last_incident_at).isoformat() if last_incident_at else '—')} · lag {fmt_secs(lag_inc)}",
            "status_code": inc_code,
        },
        {
            "component": "Uploads (24h)",
            "status": "OK" if uploads_code == "ok" else "Atención" if uploads_code == "warning" else "Crítico",
            "detail": f"Uploads: {uploads_24h} · fallidos: {uploads_failed_24h}",
            "status_code": uploads_code,
        },
    ]

    return {"items": items}

