# app/routers/entities.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from app.db import get_db
from app.models.entity import Entity
from app.models.incident_entity import IncidentEntity
from app.routers.auth import get_current_user  # type: ignore

router = APIRouter(prefix="/entities", tags=["Entities"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _entity_state(ent: Entity) -> str:
    attrs = ent.attrs if isinstance(ent.attrs, dict) else {}
    st = str(attrs.get("state") or "").strip().lower()
    if st in ("open", "closed"):
        return st
    return "open"


def _set_entity_state(ent: Entity, state: str, *, by: str, at: datetime) -> None:
    # ✅ Importante: copiar (evita mutación in-place y ayuda al dirty tracking)
    base = ent.attrs if isinstance(ent.attrs, dict) else {}
    attrs: Dict[str, Any] = dict(base)

    attrs["state"] = state
    if state == "closed":
        attrs["closed_at"] = at.isoformat()
        attrs["closed_by"] = by
    else:
        attrs.pop("closed_at", None)
        attrs.pop("closed_by", None)

    ent.attrs = attrs
    # ✅ fuerza a SQLAlchemy a considerar el JSONB como modificado (por si acaso)
    try:
        flag_modified(ent, "attrs")
    except Exception:
        pass


def _entity_servers(ent: Entity) -> List[str]:
    """
    Intentamos soportar varias formas:
      - attrs.servers = ["svde052", ...]
      - attrs.server = "svde052"
      - attrs.host / attrs.hostname (por si lo guardas así)
    """
    attrs = ent.attrs if isinstance(ent.attrs, dict) else {}
    out: List[str] = []

    s = attrs.get("servers")
    if isinstance(s, list):
        out.extend([str(x) for x in s if str(x).strip()])

    for k in ("server", "host", "hostname"):
        v = attrs.get(k)
        if v is not None and str(v).strip():
            out.append(str(v).strip())

    # unique preserving order
    seen = set()
    uniq: List[str] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _severity_bucket(ent_sev: str) -> str:
    """
    Normaliza severidad de entity a buckets del UI:
      - critical/high -> high
      - medium -> medium
      - low -> low
      - clean/""/None -> info
    """
    s = str(ent_sev or "").strip().lower()
    if s in ("critical", "high"):
        return "high"
    if s == "medium":
        return "medium"
    if s == "low":
        return "low"
    return "info"


class EntitiesListResponse(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


class EntityStatePatch(BaseModel):
    state: str  # open/closed


@router.get("", response_model=EntitiesListResponse)
def list_entities(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
    incident_id: Optional[int] = Query(default=None),
    state: str = Query(default="all"),  # open/closed/all
    entity_type: Optional[str] = Query(default=None),  # ip/host/user...
    q: Optional[str] = Query(default=None),

    # ✅ filtros
    server: Optional[str] = Query(default=None),        # svde052, etc.
    days: Optional[int] = Query(default=None, ge=1, le=3650),  # 1.. (10 años)
    severity: str = Query(default="all"),               # all|high|medium|low|info

    # paging
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> EntitiesListResponse:
    query = db.query(Entity)

    # incidente -> ids
    if incident_id is not None:
        ids = [
            int(x[0])
            for x in db.query(IncidentEntity.entity_id)
            .filter(IncidentEntity.incident_id == int(incident_id))
            .all()
        ]
        if not ids:
            return EntitiesListResponse(items=[], total=0, limit=int(limit), offset=int(offset))
        query = query.filter(Entity.id.in_(ids))

    if entity_type and entity_type != "all":
        query = query.filter(Entity.entity_type == entity_type)

    if q:
        needle = q.strip()
        if needle:
            query = query.filter(Entity.entity_key.ilike(f"%{needle}%"))

    rows = query.order_by(Entity.score_current.desc(), Entity.updated_at.desc()).all()

    # state (attrs) en python
    if state != "all":
        state_l = state.strip().lower()
        rows = [e for e in rows if _entity_state(e) == state_l]

    # server en python (attrs.servers / attrs.server)
    if server and server.strip() and server.strip().lower() != "all":
        sv = server.strip()
        rows = [e for e in rows if sv in _entity_servers(e)]

    # days en python (por last_seen_at)
    if days is not None:
        since = _utc_now() - timedelta(days=int(days))

        def _in_range(e: Entity) -> bool:
            if not e.last_seen_at:
                return True
            try:
                return e.last_seen_at >= since
            except Exception:
                return True

        rows = [e for e in rows if _in_range(e)]

    # severity bucket en python
    sev = (severity or "all").strip().lower()
    if sev != "all":
        rows = [e for e in rows if _severity_bucket(getattr(e, "severity", "") or "") == sev]

    total = len(rows)
    page = rows[offset: offset + limit]

    items: List[Dict[str, Any]] = []
    for e in page:
        items.append({
            "id": int(e.id),
            "entity_type": e.entity_type,
            "entity_key": e.entity_key,
            "scope": e.scope,
            "score_current": int(e.score_current or 0),
            "severity": e.severity,
            "state": _entity_state(e),
            "first_seen_at": e.first_seen_at.isoformat() if e.first_seen_at else None,
            "last_seen_at": e.last_seen_at.isoformat() if e.last_seen_at else None,
            "attrs": e.attrs if isinstance(e.attrs, dict) else {},
            "updated_at": e.updated_at.isoformat() if e.updated_at else None,
        })

    return EntitiesListResponse(items=items, total=int(total), limit=int(limit), offset=int(offset))


@router.patch("/{entity_id}/state")
def patch_entity_state(
    entity_id: int,
    payload: EntityStatePatch,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    ent = db.query(Entity).filter(Entity.id == entity_id).first()
    if not ent:
        raise HTTPException(status_code=404, detail="Entity not found")

    st = (payload.state or "").strip().lower()
    if st not in ("open", "closed"):
        raise HTTPException(status_code=400, detail="state must be open or closed")

    by = getattr(current_user, "email", None) or getattr(current_user, "full_name", None) or "system"
    now = _utc_now()

    # 1) Calcula el nuevo attrs (merge + state)
    base = ent.attrs if isinstance(ent.attrs, dict) else {}
    new_attrs: Dict[str, Any] = dict(base)
    new_attrs["state"] = st
    if st == "closed":
        new_attrs["closed_at"] = now.isoformat()
        new_attrs["closed_by"] = by
    else:
        new_attrs.pop("closed_at", None)
        new_attrs.pop("closed_by", None)

    # 2) ✅ UPDATE explícito (evita que el JSONB “no se ensucie” y no persista)
    updated = (
        db.query(Entity)
        .filter(Entity.id == entity_id)
        .update({Entity.attrs: new_attrs}, synchronize_session=False)
    )
    if updated != 1:
        raise HTTPException(status_code=500, detail="Could not update entity state")

    db.commit()

    # 3) refresca objeto para respuesta consistente
    db.refresh(ent)

    return {"id": int(ent.id), "state": _entity_state(ent)}

