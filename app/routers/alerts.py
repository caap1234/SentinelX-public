# app/routers/alerts.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session
import sqlalchemy as sa

from app.db import get_db
from app.models.alert import Alert
from app.models.incident_alert import IncidentAlert

from app.routers.auth import get_current_user  # type: ignore

router = APIRouter(prefix="/alerts", tags=["alerts"])


# -------------------------
# Helpers
# -------------------------
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


# ✅ Severity buckets for Alert score 0..30 (based on your rules)
# Info: 0-3
# Baja: 4-9
# Media: 10-17
# Alta: 18-24
# Crítica: 25-30
def parse_severity_filter(sev: str) -> Tuple[Optional[int], Optional[int]]:
    """
    Front manda: all | high | medium | low | info
    Alert.severity en tu sistema puede llegar hasta 30.
    """
    s = (sev or "all").lower().strip()
    if s == "all":
        return None, None
    if s == "high":
        return 18, 30
    if s == "medium":
        return 10, 17
    if s == "low":
        return 4, 9
    if s == "info":
        return 0, 3
    return None, None


def extract_ip_from_group_key(group_key: str) -> Optional[str]:
    import re

    if not group_key:
        return None
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", group_key)
    return m.group(0) if m else None


def _entity_like_conditions(
    *,
    q: str,
    server: Optional[str],
) -> List[Any]:
    """
    Filtro robusto por entidad textual (user/domain/etc).

    - Preferimos group_key porque es el "join key" natural:
        svdb057|contacto@tecnogse.com
      entonces:
        group_key ILIKE '%|contacto@tecnogse.com'
      y si hay server:
        group_key = 'svdb057|contacto@tecnogse.com' (match exacto)
        o fallback ILIKE '%|contacto@...'
    - Como fallback, buscamos también en evidence/metrics (por si alguna regla no mete la entidad en group_key).
    """
    needle = (q or "").strip()
    if not needle:
        return []

    like_tail = f"%|{needle}%"
    conds: List[Any] = []

    # exact match si hay server (mejor precisión)
    if server and server.strip():
        exact = f"{server.strip()}|{needle}"
        conds.append(Alert.group_key == exact)

    # contains tail
    conds.append(Alert.group_key.ilike(like_tail))

    # fallback: JSON text search (menos exacto, pero rescata reglas raras)
    needle_like = f"%{needle}%"
    conds.append(sa.cast(Alert.evidence, sa.Text).ilike(needle_like))
    conds.append(sa.cast(Alert.metrics, sa.Text).ilike(needle_like))

    return conds


def build_filters(
    *,
    server: Optional[str],
    status: Optional[str],
    days: int,
    severity: str,
    ip: Optional[str],
    q: Optional[str],
    incident_id: Optional[int],
):
    conds: List[Any] = []

    # rango de tiempo
    since = utc_now() - timedelta(days=max(1, int(days or 7)))
    conds.append(Alert.triggered_at >= since)

    if server:
        conds.append(Alert.server == server)

    # status UI -> DB
    st_ui = (status or "all").lower().strip()
    if st_ui != "all":
        st_db = _status_ui_to_db(st_ui)
        if st_db == "open":
            conds.append(Alert.status.in_(["open", "triage", "contained"]))
        else:
            conds.append(Alert.status == st_db)

    # severity bucket
    mn, mx = parse_severity_filter(severity)
    if mn is not None and mx is not None:
        conds.append(and_(Alert.severity >= mn, Alert.severity <= mx))

    # ip (no hay columna ip; se busca en group_key o JSON)
    if ip:
        ip_s = ip.strip()
        if ip_s:
            ip_like = f"%{ip_s}%"
            conds.append(
                or_(
                    Alert.group_key.ilike(ip_like),
                    sa.cast(Alert.evidence, sa.Text).ilike(ip_like),
                    sa.cast(Alert.metrics, sa.Text).ilike(ip_like),
                )
            )

    # q (entidad: user/domain/etc)
    if q:
        q_s = q.strip()
        if q_s:
            ent_conds = _entity_like_conditions(q=q_s, server=server)
            # Importante: debe ser OR dentro, pero AND con el resto de filtros
            conds.append(or_(*ent_conds))

    # incident_id (filtrado real vía incident_alerts) se aplica en la query con JOIN

    return conds


def sev_label(sev: int) -> str:
    """
    Labels para score 0..30
    """
    if sev >= 25:
        return "Crítica"
    if sev >= 18:
        return "Alta"
    if sev >= 10:
        return "Media"
    if sev >= 4:
        return "Baja"
    return "Info"


def sev_level(sev: int) -> str:
    """
    Levels para UI (badge colors)
    high: 18..30
    medium: 10..17
    low: 4..9
    info: 0..3
    """
    if sev >= 18:
        return "high"
    if sev >= 10:
        return "medium"
    if sev >= 4:
        return "low"
    return "info"


def pretty_json(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(obj)


# -------------------------
# Schemas
# -------------------------
class AlertListItem(BaseModel):
    id: int
    datetime: str
    level: str
    severityLabel: str
    severity: int
    type: str  # rule_name o rule_id
    ip: Optional[str] = None
    server: Optional[str] = None
    description: Optional[str] = None
    status: str  # UI status


class AlertListResponse(BaseModel):
    total: int
    items: List[AlertListItem]


class AlertDetailResponse(BaseModel):
    id: int
    timestamp_utc: str
    timestamp_local: Optional[str] = None
    server: Optional[str] = None

    rule_id: Optional[int] = None
    rule_name: str

    severity: int
    severity_label: str
    level: str

    status: str  # UI status
    disposition: Optional[str] = None
    note: Optional[str] = None

    source: Optional[str] = None
    event_type: Optional[str] = None
    group_key: str

    metrics: Dict[str, Any] = Field(default_factory=dict)
    evidence: Dict[str, Any] = Field(default_factory=dict)

    ip: Optional[str] = None

    raw_log_snippet: str = "—"


class AlertUpdateRequest(BaseModel):
    status: Optional[str] = None  # open/resolved/false_positive
    disposition: Optional[str] = None
    note: Optional[str] = None  # resolution_note
    category: Optional[str] = None  # ignorado


class BulkUpdateRequest(BaseModel):
    select_all: bool = False
    ids: Optional[List[int]] = None

    # filtros cuando select_all=true
    server: Optional[str] = None
    incident_id: Optional[int] = None
    ip: Optional[str] = None
    q: Optional[str] = None  # ✅ NUEVO: entidad (user/domain/etc)
    days: int = 7
    severity: str = "all"
    status_filter: str = "all"  # UI status

    status: str  # UI status
    category: Optional[str] = None
    disposition: Optional[str] = None
    note: Optional[str] = None


# -------------------------
# Endpoints
# -------------------------
@router.get("", response_model=AlertListResponse)
def list_alerts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    days: int = Query(7, ge=1, le=3650),
    severity: str = Query("all"),
    status: str = Query("open"),  # UI
    server: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    q: Optional[str] = Query(None),  # ✅ NUEVO: filtro por entidad (front modal usa q)
    incident_id: Optional[int] = Query(None),
):
    conds = build_filters(
        server=server,
        status=status,
        days=days,
        severity=severity,
        ip=ip,
        q=q,
        incident_id=incident_id,
    )

    stmt = select(Alert)

    # ✅ filtro real por incident_id (JOIN)
    if incident_id is not None:
        stmt = (
            stmt.join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
            .where(IncidentAlert.incident_id == int(incident_id))
        )

    stmt = stmt.where(and_(*conds)).order_by(Alert.triggered_at.desc(), Alert.id.desc())

    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = db.execute(stmt.limit(limit).offset(offset)).scalars().all()

    items: List[AlertListItem] = []
    for a in rows:
        ip_guess = None
        if isinstance(a.evidence, dict):
            ip_guess = a.evidence.get("ip") or a.evidence.get("ip_client")
        if not ip_guess and isinstance(a.metrics, dict):
            ip_guess = a.metrics.get("ip") or a.metrics.get("ip_client")
        if not ip_guess:
            ip_guess = extract_ip_from_group_key(a.group_key)

        sev = int(a.severity or 0)

        items.append(
            AlertListItem(
                id=int(a.id),
                datetime=a.triggered_at.astimezone(timezone.utc).isoformat(),
                level=sev_level(sev),
                severityLabel=sev_label(sev),
                severity=sev,
                type=(a.rule_name or (f"rule:{a.rule_id}" if a.rule_id else "—")),
                ip=ip_guess,
                server=a.server,
                description=f"{a.rule_name} · {a.group_key}"[:240],
                status=_status_db_to_ui(a.status or "open"),
            )
        )

    return AlertListResponse(total=int(total), items=items)


@router.get("/{alert_id}", response_model=AlertDetailResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    a: Alert | None = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")

    ip_guess = None
    if isinstance(a.evidence, dict):
        ip_guess = a.evidence.get("ip") or a.evidence.get("ip_client")
    if not ip_guess and isinstance(a.metrics, dict):
        ip_guess = a.metrics.get("ip") or a.metrics.get("ip_client")
    if not ip_guess:
        ip_guess = extract_ip_from_group_key(a.group_key)

    raw: Any = "—"
    if isinstance(a.evidence, dict):
        raw = a.evidence.get("raw") or a.evidence.get("sample") or a.evidence.get("log") or None
    if not raw:
        raw = pretty_json(a.evidence or {})

    sev = int(a.severity or 0)

    return AlertDetailResponse(
        id=int(a.id),
        timestamp_utc=a.triggered_at.astimezone(timezone.utc).isoformat(),
        server=a.server,
        rule_id=a.rule_id,
        rule_name=a.rule_name,
        severity=sev,
        severity_label=sev_label(sev),
        level=sev_level(sev),
        status=_status_db_to_ui(a.status or "open"),
        disposition=a.disposition,
        note=a.resolution_note,
        source=a.source,
        event_type=a.event_type,
        group_key=a.group_key,
        metrics=a.metrics or {},
        evidence=a.evidence or {},
        ip=ip_guess,
        raw_log_snippet=str(raw)[:6000],
    )


@router.patch("/{alert_id}", response_model=AlertDetailResponse)
def update_alert(
    alert_id: int,
    payload: AlertUpdateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    a: Alert | None = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")

    if payload.status:
        st_ui = payload.status.strip().lower()
        if st_ui not in ("open", "resolved", "false_positive"):
            raise HTTPException(status_code=422, detail="Invalid status")

        st_db = _status_ui_to_db(st_ui)
        a.status = st_db

        if st_db in ("closed", "false_positive"):
            a.resolved_at = utc_now()
        else:
            a.resolved_at = None

    if payload.disposition is not None:
        a.disposition = payload.disposition.strip() or None

    if payload.note is not None:
        a.resolution_note = payload.note.strip() or None

    db.add(a)
    db.commit()
    db.refresh(a)

    return get_alert(alert_id=a.id, db=db, current_user=current_user)


@router.patch("/status/bulk")
def bulk_update_status(
    payload: BulkUpdateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    st_ui = (payload.status or "").strip().lower()
    if st_ui not in ("open", "resolved", "false_positive"):
        raise HTTPException(status_code=422, detail="Invalid status")

    st_db = _status_ui_to_db(st_ui)
    disp = payload.disposition.strip() if payload.disposition else None
    note = payload.note.strip() if payload.note else None

    values: Dict[str, Any] = {"status": st_db}
    if disp is not None:
        values["disposition"] = disp or None
    if note is not None:
        values["resolution_note"] = note or None

    if st_db in ("closed", "false_positive"):
        values["resolved_at"] = utc_now()
    else:
        values["resolved_at"] = None

    if payload.select_all:
        conds = build_filters(
            server=payload.server or None,
            status=payload.status_filter or "all",
            days=int(payload.days or 7),
            severity=payload.severity or "all",
            ip=payload.ip or None,
            q=payload.q or None,  # ✅ NUEVO
            incident_id=payload.incident_id if payload.incident_id else None,
        )

        upd = update(Alert).where(and_(*conds))

        if payload.incident_id is not None:
            sub = select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == int(payload.incident_id))
            upd = upd.where(Alert.id.in_(sub))

        upd = upd.values(**values)
        res = db.execute(upd)
        db.commit()
        return {"ok": True, "updated": int(res.rowcount or 0), "mode": "select_all"}

    ids = payload.ids or []
    ids = [int(x) for x in ids if x is not None]
    if not ids:
        raise HTTPException(status_code=422, detail="ids is required when select_all=false")

    upd = update(Alert).where(Alert.id.in_(ids)).values(**values)
    res = db.execute(upd)
    db.commit()
    return {"ok": True, "updated": int(res.rowcount or 0), "mode": "ids"}


@router.get("/servers", response_model=List[Dict[str, str]])
def list_alert_servers(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    rows = db.execute(
        select(Alert.server)
        .where(Alert.server.isnot(None))
        .group_by(Alert.server)
        .order_by(Alert.server.asc())
    ).scalars().all()

    return [{"id": s, "label": s} for s in rows if s]

