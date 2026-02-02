from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    Text,
    UniqueConstraint,
    Index,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base


class RuleStateV2(Base):
    __tablename__ = "rule_states_v2"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    rule_id = Column(Integer, ForeignKey("rules_v2.id", ondelete="CASCADE"), nullable=False)
    group_key = Column(Text, nullable=False)

    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_alert_at = Column(DateTime(timezone=True), nullable=True)

    extra = Column(JSONB, nullable=False, server_default="{}")
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    rule = relationship("RuleV2", back_populates="states")

    __table_args__ = (
        # CLAVE para evitar duplicados y habilitar ON CONFLICT(rule_id, group_key)
        UniqueConstraint("rule_id", "group_key", name="uq_rule_states_v2_rule_id_group_key"),
        # Índice útil para búsquedas frecuentes (además del UNIQUE)
        Index("ix_rule_states_v2_rule_id_group_key", "rule_id", "group_key"),
    )

