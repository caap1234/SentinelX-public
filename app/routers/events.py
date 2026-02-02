from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.schemas.events import EventFilter, EventListOut, EventOut, PageMeta
from app.services.events import get_event, list_events
from app.routers.auth import get_current_user  # ✅ aquí está tu dependencia real

router = APIRouter(
    prefix="/events",
    tags=["events"],
    dependencies=[Depends(get_current_user)],  # ✅ requiere JWT
)


@router.get("", response_model=EventListOut)
def events_list(
    db: Session = Depends(get_db),
    # filtros
    start: Optional[datetime] = Query(default=None),
    end: Optional[datetime] = Query(default=None),
    server: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    service: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
    severity_min: Optional[int] = Query(default=None, ge=0, le=10),
    severity_max: Optional[int] = Query(default=None, ge=0, le=10),
    q: Optional[str] = Query(default=None),
    # paginación
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    f = EventFilter(
        start=start,
        end=end,
        server=server,
        source=source,
        service=service,
        rule_id=rule_id,
        severity_min=severity_min,
        severity_max=severity_max,
        q=q,
        limit=limit,
        offset=offset,
    )

    items, returned = list_events(db, f)

    return EventListOut(
        items=[EventOut.model_validate(x) for x in items],
        meta=PageMeta(limit=limit, offset=offset, returned=returned),
    )


@router.get("/{event_id}", response_model=EventOut)
def events_get(
    event_id: int,
    db: Session = Depends(get_db),
):
    ev = get_event(db, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return EventOut.model_validate(ev)
