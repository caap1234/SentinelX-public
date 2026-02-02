# app/schemas/events.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, List
from uuid import UUID

from pydantic import BaseModel, Field


class EventIn(BaseModel):
    timestamp_utc: datetime
    server: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=255)
    service: str = Field(min_length=1, max_length=255)

    message: str = Field(min_length=1, max_length=4096)
    extra: Dict[str, Any] = Field(default_factory=dict)

    log_upload_id: Optional[int] = None
    raw_id: Optional[int] = None  # BigInt

    class Config:
        extra = "forbid"


class EventOut(BaseModel):
    id: UUID
    timestamp_utc: datetime
    server: str
    source: str
    service: str

    ip_client: Optional[str] = None
    ip_server: Optional[str] = None

    domain: Optional[str] = None
    username: Optional[str] = None

    message: str
    extra: Dict[str, Any]

    created_at: datetime

    log_upload_id: Optional[int] = None
    raw_id: Optional[int] = None

    class Config:
        from_attributes = True


class EventFilter(BaseModel):
    start: Optional[datetime] = None
    end: Optional[datetime] = None

    server: Optional[str] = None
    source: Optional[str] = None
    service: Optional[str] = None

    # búsqueda libre
    q: Optional[str] = None

    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class PageMeta(BaseModel):
    limit: int
    offset: int
    returned: int


class EventListOut(BaseModel):
    items: List[EventOut]
    meta: PageMeta
