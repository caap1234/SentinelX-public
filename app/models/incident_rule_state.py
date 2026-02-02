from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, Text, ForeignKey, func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class IncidentRuleState(Base):
    __tablename__ = "incident_rule_state"

    id = Column(Integer, primary_key=True, autoincrement=True)

    rule_id = Column(Integer, ForeignKey("incident_rules.id", ondelete="CASCADE"), nullable=False)
    group_key = Column(Text, nullable=False)

    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_incident_at = Column(DateTime(timezone=True), nullable=True)

    extra = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    rule = relationship("IncidentRule", lazy="joined")
