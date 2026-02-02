from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, String, UniqueConstraint, func

from app.db import Base


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    incident_id = Column(BigInteger, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)

    role = Column(String(32), nullable=False, server_default="supporting")  # trigger/supporting

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),
    )
