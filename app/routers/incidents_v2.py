from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.models.entity import Entity
from app.models.incident import Incident
from app.models.incident_alert import IncidentAlert
from app.models.incident_entity import IncidentEntity

# ✅ usar tu auth router
from app.routers.auth import get_current_user  # type: ignore


router = APIRouter(prefix="/incidents", tags=["Incidents"])


# -----------------------------
# Helpers
# -----------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _status_ui_to_db(status: str) -> str:
    """
    UI: open/resolved/false_positive
    DB: open/triage/contained/closed/false_positive
    """
    s = (status or "").strip().lower()
    if s == "resolved":
        return "closed"
    if s in ("open", "triage", "contained", "closed", "false_positive"):
        return s
    return "open"


def _status_db_to_ui(status: str) -> str:
    s = (status or "").strip().lower()
    if s == "closed":
        return "resolved"
    if s in ("open", "false_positive"):
        return s
    if s in ("triage", "contained"):
        return "open"
    return "open"


def _entity_state(ent: Entity) -> str:
    """
    Entity no tiene status en columnas.
    Usamos attrs.state: open/closed. Si no existe -> open (estricto).
    """
    attrs = ent.attrs if isinstance(ent.attrs, dict) else {}
    st = str(attrs.get("state") or "").strip().lower()
    if st in ("closed", "open"):
        return st
    return "open"


def _set_entity_state(ent: Entity, state: str, *, by: str, at: datetime) -> None:
    attrs = ent.attrs if isinstance(ent.attrs, dict) else {}
    attrs["state"] = state
    if state == "closed":
        attrs["closed_at"] = at.isoformat()
        attrs["closed_by"] = by
    else:
        # reopen
        attrs.pop("closed_at", None)
        attrs.pop("closed_by", None)
    ent.attrs = attrs


def _since_days(days: int) -> datetime:
    days = max(1, int(days))
    return _utc_now() - timedelta(days=days)


def _badge_from_score(score: int) -> str:
    """
    UI badge por score:
      0-30  => low
      31-60 => medium
      61-100=> high
    """
    n = int(score or 0)
    if n >= 61:
        return "high"
    if n >= 31:
        return "medium"
    return "low"


def _severity_label_from_badge(badge: str) -> str:
    if badge == "high":
        return "Alta"
    if badge == "medium":
        return "Media"
    return "Baja"


def _incident_to_item(inc: Incident) -> Dict[str, Any]:
    score = int(inc.score or 0)
    badge = _badge_from_score(score)
    return {
        "id": int(inc.id),
        "code": inc.code,
        "name": inc.name,
        "scope": inc.scope,
        "status": _status_db_to_ui(inc.status),
        "server": inc.server,
        "score": score,
        "badge": badge,  # ✅ para UI (low/medium/high)
        "severityLabel": _severity_label_from_badge(badge),
        "primary_entity_type": inc.primary_entity_type,
        "primary_entity_key": inc.primary_entity_key,
        "opened_at": inc.opened_at.isoformat() if inc.opened_at else None,
        "last_activity_at": inc.last_activity_at.isoformat() if inc.last_activity_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


# -----------------------------
# Schemas
# -----------------------------

class IncidentListResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


class IncidentAlertDTO(BaseModel):
    id: int
    rule_id: Optional[int] = None
    rule_name: str
    severity: int
    server: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    group_key: str
    triggered_at: datetime
    status: str
    disposition: Optional[str] = None
    resolution_note: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class IncidentEntityDTO(BaseModel):
    id: int
    entity_type: str
    entity_key: str
    scope: str
    score_current: int
    severity: str
    state: str  # open/closed (attrs.state)
    relation: str


class IncidentDetailResponse(BaseModel):
    id: int
    code: str
    name: str
    scope: str
    status: str
    server: Optional[str] = None

    score: int
    badge: str
    severityLabel: str

    primary_entity_type: str
    primary_entity_key: str

    metrics: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    opened_at: datetime
    last_activity_at: datetime
    closed_at: Optional[datetime] = None

    disposition: Optional[str] = None
    resolution_note: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None

    alerts: List[IncidentAlertDTO] = Field(default_factory=list)
    entities: List[IncidentEntityDTO] = Field(default_factory=list)

    # ✅ pendientes para la regla obligatoria
    open_alerts_count: int = 0
    open_entities_count: int = 0


class IncidentStatusPatch(BaseModel):
    status: str  # open/resolved/false_positive
    category: Optional[str] = None
    disposition: Optional[str] = None
    resolution_note: Optional[str] = None


class IncidentStatusPatchResponse(BaseModel):
    id: int
    status: str  # UI status final (puede quedarse open si blocked)
    blocked: bool = False

    open_alerts_count: int = 0
    open_entities_count: int = 0

    # para navegación/acciones
    related_alert_ids: List[int] = Field(default_factory=list)
    related_entity_ids: List[int] = Field(default_factory=list)

    message: Optional[str] = None


# -----------------------------
# Internal: load related
# -----------------------------

def _related_alert_ids(db: Session, incident_id: int) -> List[int]:
    rows = db.query(IncidentAlert.alert_id).filter(IncidentAlert.incident_id == incident_id).all()
    out: List[int] = []
    for (aid,) in rows:
        try:
            out.append(int(aid))
        except Exception:
            pass
    return out


def _related_entity_ids(db: Session, incident_id: int) -> List[int]:
    rows = db.query(IncidentEntity.entity_id).filter(IncidentEntity.incident_id == incident_id).all()
    out: List[int] = []
    for (eid,) in rows:
        try:
            out.append(int(eid))
        except Exception:
            pass
    return out


def _count_open_alerts(db: Session, alert_ids: List[int]) -> Tuple[int, List[int]]:
    if not alert_ids:
        return 0, []
    rows = (
        db.query(Alert.id, Alert.status)
        .filter(Alert.id.in_(alert_ids))
        .all()
    )
    open_ids: List[int] = []
    for aid, st in rows:
        ui = _status_db_to_ui(st)
        if ui == "open":
            open_ids.append(int(aid))
    return len(open_ids), open_ids


def _count_open_entities(db: Session, entity_ids: List[int]) -> Tuple[int, List[int]]:
    if not entity_ids:
        return 0, []
    ents = db.query(Entity).filter(Entity.id.in_(entity_ids)).all()
    open_ids: List[int] = []
    for e in ents:
        if _entity_state(e) == "open":
            open_ids.append(int(e.id))
    return len(open_ids), open_ids


# -----------------------------
# Routes
# -----------------------------

@router.get("", response_model=IncidentListResponse)
def list_incidents(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    server: Optional[str] = Query(default=None),
    severity: str = Query(default="all"),  # low/medium/high/all (por score)
    status: str = Query(default="all"),    # open/resolved/false_positive/all
    days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> IncidentListResponse:
    since = _since_days(days)

    q = db.query(Incident).filter(Incident.last_activity_at >= since)

    if server and server != "all":
        q = q.filter(Incident.server == server)

    if status and status != "all":
        db_status = _status_ui_to_db(status)
        if db_status == "open":
            q = q.filter(Incident.status.in_(["open", "triage", "contained"]))
        else:
            q = q.filter(Incident.status == db_status)

    if severity and severity != "all":
        if severity == "high":
            q = q.filter(Incident.score >= 61)
        elif severity == "medium":
            q = q.filter(Incident.score >= 31, Incident.score <= 60)
        elif severity == "low":
            q = q.filter(Incident.score <= 30)

    total = q.count()
    rows = (
        q.order_by(Incident.last_activity_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return IncidentListResponse(
        items=[_incident_to_item(x) for x in rows],
        total=int(total),
        limit=int(limit),
        offset=int(offset),
    )


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
def get_incident_detail(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> IncidentDetailResponse:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert_ids = _related_alert_ids(db, incident_id)
    entity_ids = _related_entity_ids(db, incident_id)

    alerts: List[Alert] = []
    if alert_ids:
        alerts = (
            db.query(Alert)
            .filter(Alert.id.in_(alert_ids))
            .order_by(Alert.triggered_at.desc())
            .all()
        )

    entities: List[Entity] = []
    if entity_ids:
        entities = db.query(Entity).filter(Entity.id.in_(entity_ids)).all()

    # relation map
    rel_map: Dict[int, str] = {}
    for row in db.query(IncidentEntity.entity_id, IncidentEntity.relation).filter(IncidentEntity.incident_id == incident_id).all():
        try:
            rel_map[int(row[0])] = str(row[1] or "related")
        except Exception:
            pass

    open_alerts_count, _open_alert_ids = _count_open_alerts(db, alert_ids)
    open_entities_count, _open_entity_ids = _count_open_entities(db, entity_ids)

    score = int(inc.score or 0)
    badge = _badge_from_score(score)

    return IncidentDetailResponse(
        id=int(inc.id),
        code=inc.code,
        name=inc.name,
        scope=inc.scope,
        status=_status_db_to_ui(inc.status),
        server=inc.server,

        score=score,
        badge=badge,
        severityLabel=_severity_label_from_badge(badge),

        primary_entity_type=inc.primary_entity_type,
        primary_entity_key=inc.primary_entity_key,

        metrics=inc.metrics if isinstance(inc.metrics, dict) else {},
        evidence=inc.evidence if isinstance(inc.evidence, dict) else {},

        opened_at=inc.opened_at,
        last_activity_at=inc.last_activity_at,
        closed_at=inc.closed_at,

        disposition=inc.disposition,
        resolution_note=inc.resolution_note,
        resolved_by=inc.resolved_by,
        resolved_at=inc.resolved_at,

        alerts=[
            IncidentAlertDTO(
                id=int(a.id),
                rule_id=int(a.rule_id) if a.rule_id is not None else None,
                rule_name=a.rule_name,
                severity=int(a.severity or 0),
                server=a.server,
                source=a.source,
                event_type=a.event_type,
                group_key=a.group_key,
                triggered_at=a.triggered_at,
                status=_status_db_to_ui(a.status),
                disposition=a.disposition,
                resolution_note=a.resolution_note,
                evidence=a.evidence if isinstance(a.evidence, dict) else {},
                metrics=a.metrics if isinstance(a.metrics, dict) else {},
            )
            for a in alerts
        ],
        entities=[
            IncidentEntityDTO(
                id=int(e.id),
                entity_type=e.entity_type,
                entity_key=e.entity_key,
                scope=e.scope,
                score_current=int(e.score_current or 0),
                severity=e.severity,
                state=_entity_state(e),
                relation=rel_map.get(int(e.id), "related"),
            )
            for e in entities
        ],
        open_alerts_count=int(open_alerts_count),
        open_entities_count=int(open_entities_count),
    )


@router.patch("/{incident_id}/status", response_model=IncidentStatusPatchResponse)
def patch_incident_status(
    incident_id: int,
    payload: IncidentStatusPatch,
    cascade: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> IncidentStatusPatchResponse:
    """
    Regla obligatoria:
    - Si pides resolved/false_positive y hay alertas abiertas o entidades abiertas:
        * si cascade=false -> NO cerramos incidente (queda open) y respondemos blocked=true (200)
        * si cascade=true  -> cerramos en cascada alertas + entities, y cerramos incidente
    - Nunca respondemos 409.
    """
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    now = _utc_now()
    by = getattr(current_user, "email", None) or getattr(current_user, "full_name", None) or "system"

    requested_db = _status_ui_to_db(payload.status)
    requested_ui = _status_db_to_ui(requested_db)

    alert_ids = _related_alert_ids(db, incident_id)
    entity_ids = _related_entity_ids(db, incident_id)

    open_alerts_count, open_alert_ids = _count_open_alerts(db, alert_ids)
    open_entities_count, open_entity_ids = _count_open_entities(db, entity_ids)

    wants_close = requested_db in ("closed", "false_positive")

    # Guardar metadatos aunque quede bloqueado (opcional)
    if payload.category:
        inc.disposition = payload.category
    if payload.disposition:
        inc.disposition = payload.disposition
    if payload.resolution_note:
        inc.resolution_note = payload.resolution_note

    if wants_close and (open_alerts_count > 0 or open_entities_count > 0) and not cascade:
        # NO cerramos incidente
        inc.status = "open"
        inc.updated_at = now
        db.add(inc)
        db.commit()

        return IncidentStatusPatchResponse(
            id=int(inc.id),
            status="open",
            blocked=True,
            open_alerts_count=int(open_alerts_count),
            open_entities_count=int(open_entities_count),
            related_alert_ids=[int(x) for x in alert_ids],
            related_entity_ids=[int(x) for x in entity_ids],
            message="Este incidente tiene alertas o entidades abiertas. Ciérralo en cascada o gestiona por separado.",
        )

    # Si no quiere cerrar, o ya no hay pendientes, o cascade=true: aplicamos
    if wants_close and cascade:
        # cerrar alertas relacionadas (todas)
        if alert_ids:
            alerts = db.query(Alert).filter(Alert.id.in_(alert_ids)).all()
            for a in alerts:
                # marcamos estado final del alert coherente con el incidente
                a.status = requested_db  # closed/false_positive
                if payload.disposition:
                    a.disposition = payload.disposition
                if payload.resolution_note:
                    a.resolution_note = payload.resolution_note
                a.resolved_at = now
                a.resolved_by = by
                db.add(a)

        # cerrar entidades relacionadas (todas) usando attrs.state
        if entity_ids:
            ents = db.query(Entity).filter(Entity.id.in_(entity_ids)).all()
            for e in ents:
                _set_entity_state(e, "closed", by=by, at=now)
                db.add(e)

        # recalc pendientes post-cascada
        open_alerts_count, open_alert_ids = _count_open_alerts(db, alert_ids)
        open_entities_count, open_entity_ids = _count_open_entities(db, entity_ids)

    # Ahora sí: solo cerramos incidente si ya no hay pendientes
    if wants_close and (open_alerts_count > 0 or open_entities_count > 0):
        inc.status = "open"
        inc.updated_at = now
        db.add(inc)
        db.commit()

        return IncidentStatusPatchResponse(
            id=int(inc.id),
            status="open",
            blocked=True,
            open_alerts_count=int(open_alerts_count),
            open_entities_count=int(open_entities_count),
            related_alert_ids=[int(x) for x in alert_ids],
            related_entity_ids=[int(x) for x in entity_ids],
            message="Aún existen pendientes. El incidente permanece abierto.",
        )

    # Aplicar status final (open o closed/false_positive)
    inc.status = requested_db if requested_db != "closed" else "closed"
    inc.updated_at = now

    if wants_close:
        inc.resolved_at = now
        inc.resolved_by = by
        inc.closed_at = now
    else:
        inc.resolved_at = None
        inc.resolved_by = None
        inc.closed_at = None

    db.add(inc)
    db.commit()

    return IncidentStatusPatchResponse(
        id=int(inc.id),
        status=_status_db_to_ui(inc.status),
        blocked=False,
        open_alerts_count=int(open_alerts_count),
        open_entities_count=int(open_entities_count),
        related_alert_ids=[int(x) for x in alert_ids],
        related_entity_ids=[int(x) for x in entity_ids],
        message=None,
    )
