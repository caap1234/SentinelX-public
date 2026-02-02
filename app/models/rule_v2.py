from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import relationship

from app.db import Base


class RuleV2(Base):
    __tablename__ = "rules_v2"

    id = Column(Integer, primary_key=True, autoincrement=True)

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    enabled = Column(Boolean, nullable=False, server_default="true")

    source = Column(String(64), nullable=False)       # APACHE_ACCESS, EXIM_MAINLOG, etc.
    event_type = Column(String(64), nullable=False)   # http_access, auth_login, etc.

    severity = Column(Integer, nullable=False, server_default="3")

    match = Column(JSONB, nullable=False, server_default="{}")
    group_by = Column(ARRAY(Text), nullable=False, server_default="{}")
    window_seconds = Column(Integer, nullable=False, server_default="300")
    let = Column(JSONB, nullable=False, server_default="{}")
    condition = Column(Text, nullable=False, server_default="")
    cooldown_seconds = Column(Integer, nullable=False, server_default="900")
    evidence = Column(JSONB, nullable=False, server_default="{}")
    emit = Column(JSONB, nullable=False, server_default="{}")

    tags = Column(ARRAY(Text), nullable=False, server_default="{}")
    version = Column(Integer, nullable=False, server_default="1")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    states = relationship("RuleStateV2", back_populates="rule", passive_deletes=True)
