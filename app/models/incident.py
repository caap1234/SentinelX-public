from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    code = Column(String(64), nullable=False)           # INC-ACC-01
    name = Column(String(255), nullable=False)

    scope = Column(String(16), nullable=False)          # local/global
    status = Column(String(32), nullable=False, server_default="open")  # open/triage/contained/closed/false_positive

    severity_base = Column(Integer, nullable=False)
    severity_current = Column(Integer, nullable=False)

    score = Column(Integer, nullable=False)             # base + bonus (cap opcional en lógica)

    server = Column(String(255), nullable=True)

    # entidad principal
    primary_entity_type = Column(String(32), nullable=False)
    primary_entity_key = Column(String(255), nullable=False)

    # agregados
    metrics = Column(JSONB, nullable=False, server_default="{}")
    evidence = Column(JSONB, nullable=False, server_default="{}")

    opened_at = Column(DateTime(timezone=True), nullable=False)
    last_activity_at = Column(DateTime(timezone=True), nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    disposition = Column(String(64), nullable=True)
    resolution_note = Column(Text, nullable=True)
    resolved_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
