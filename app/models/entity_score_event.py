from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class EntityScoreEvent(Base):
    __tablename__ = "entity_score_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    entity_id = Column(BigInteger, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)

    ts = Column(DateTime(timezone=True), nullable=False)
    delta = Column(Integer, nullable=False)  # +score / -decay / etc

    reason_type = Column(String(16), nullable=False)  # alert/incident/decay/manual
    reason_id = Column(String(64), nullable=True)     # alert_id / incident_id / etc

    meta = Column(JSONB, nullable=False, server_default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
