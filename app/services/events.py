from __future__ import annotations

from typing import List, Tuple

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import Event
from app.schemas.events import EventFilter


def list_events(db: Session, f: EventFilter) -> Tuple[List[Event], int]:
    stmt = select(Event)

    where = []

    if f.start is not None:
        where.append(Event.timestamp_utc >= f.start)
    if f.end is not None:
        where.append(Event.timestamp_utc <= f.end)

    if f.server:
        where.append(Event.server == f.server)
    if f.source:
        where.append(Event.source == f.source)
    if f.service:
        where.append(Event.service == f.service)
    if f.rule_id:
        where.append(Event.rule_id == f.rule_id)

    if f.severity_min is not None:
        where.append(Event.severity >= f.severity_min)
    if f.severity_max is not None:
        where.append(Event.severity <= f.severity_max)

    if f.q:
        q = f"%{f.q.strip()}%"
        where.append(or_(Event.message.ilike(q), Event.rule_name.ilike(q)))

    if where:
        stmt = stmt.where(and_(*where))

    stmt = stmt.order_by(Event.timestamp_utc.desc())
    stmt = stmt.limit(f.limit).offset(f.offset)

    items = list(db.execute(stmt).scalars().all())
    return items, len(items)


def get_event(db: Session, event_id: int) -> Event | None:
    return db.get(Event, event_id)
