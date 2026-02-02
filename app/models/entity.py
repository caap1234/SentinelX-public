from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class Entity(Base):
    __tablename__ = "entities"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    entity_type = Column(String(32), nullable=False)  # ip/user/host/asn/country/subnet24/server/domain
    entity_key = Column(String(255), nullable=False)

    scope = Column(String(16), nullable=False, server_default="local")  # local/global

    score_current = Column(Integer, nullable=False, server_default="0")  # 0..100
    severity = Column(String(16), nullable=False, server_default="clean")  # clean/low/medium/high/critical

    first_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    score_updated_at = Column(DateTime(timezone=True), nullable=True)  # para decay lazy

    attrs = Column(JSONB, nullable=False, server_default="{}")  # geo/asn/tags/flags

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_key", name="uq_entity_type_key"),
    )
