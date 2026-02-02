from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, String, UniqueConstraint, func

from app.db import Base


class IncidentEntity(Base):
    __tablename__ = "incident_entities"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    incident_id = Column(BigInteger, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    entity_id = Column(BigInteger, ForeignKey("entities.id", ondelete="CASCADE"), nullable=False)

    relation = Column(String(32), nullable=False, server_default="related")  # primary/attacker/victim/related

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("incident_id", "entity_id", name="uq_incident_entity"),
    )
