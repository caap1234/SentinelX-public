from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    rule_id = Column(Integer, ForeignKey("rules_v2.id", ondelete="SET NULL"), nullable=True)
    rule_name = Column(String(255), nullable=False)
    severity = Column(Integer, nullable=False)

    server = Column(String(255), nullable=True)
    source = Column(String(64), nullable=True)
    event_type = Column(String(64), nullable=True)

    group_key = Column(Text, nullable=False)

    triggered_at = Column(DateTime(timezone=True), nullable=False)
    window_start = Column(DateTime(timezone=True), nullable=True)
    window_end = Column(DateTime(timezone=True), nullable=True)

    metrics = Column(JSONB, nullable=False, server_default="{}")
    evidence = Column(JSONB, nullable=False, server_default="{}")

    status = Column(String(32), nullable=False, server_default="open")
    disposition = Column(String(64), nullable=True)
    resolution_note = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
