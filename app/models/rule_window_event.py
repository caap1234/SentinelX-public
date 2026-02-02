from __future__ import annotations

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db import Base


class RuleWindowEvent(Base):
    """
    Buffer distribuido (en BD) para ventanas del engine.
    Cada fila representa un evento reducido que participa en la ventana de una regla + group_key.
    """
    __tablename__ = "rule_window_events"

    id = Column(Integer, primary_key=True)

    rule_id = Column(Integer, ForeignKey("rules_v2.id", ondelete="CASCADE"), nullable=False, index=True)
    group_key = Column(String, nullable=False, index=True)

    ts = Column(DateTime(timezone=True), nullable=False, index=True, server_default=func.now())

    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"), nullable=False, index=True)

    # campos “derivados” para métricas rápidas
    server = Column(String, nullable=True)
    path = Column(String, nullable=True)
    ip_client = Column(String, nullable=True)
    ip_subnet24 = Column(String, nullable=True)
    username = Column(String, nullable=True)  # lower
    action = Column(String, nullable=True)    # fail/success

    __table_args__ = (
        # Query típico: por (rule_id, group_key) y rango de ts
        Index("ix_rwe_rule_group_ts", "rule_id", "group_key", "ts"),
    )

