# app/models/event.py
from __future__ import annotations

import uuid

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

from app.db import Base


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    timestamp_utc = Column(DateTime(timezone=True), nullable=False, index=True)

    server = Column(String(255), nullable=False, index=True)
    source = Column(String(255), nullable=False, index=True)
    service = Column(String(255), nullable=False, index=True)

    ip_client = Column(INET, nullable=True, index=True)
    ip_server = Column(INET, nullable=True)

    domain = Column(Text, nullable=True)
    username = Column(Text, nullable=True)

    message = Column(Text, nullable=False)

    # Datos normalizados/extendidos
    extra = Column(JSONB, nullable=False, server_default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relación con carga (opcional)
    log_upload_id = Column(
        Integer,
        ForeignKey("log_uploads.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    log_upload = relationship("LogUpload", back_populates="events", passive_deletes=True)

    # Relación con raw log (opcional)
    raw_id = Column(
        BigInteger,
        ForeignKey("rawlogs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rawlog = relationship("RawLog", back_populates="events", passive_deletes=True)

    # ----------------------------
    # Engine queue / processing
    # ----------------------------
    # pending -> processing -> done/error
    engine_status = Column(String(32), nullable=False, server_default="pending", index=True)
    engine_claimed_at = Column(DateTime(timezone=True), nullable=True, index=True)
    engine_processed_at = Column(DateTime(timezone=True), nullable=True, index=True)
    engine_attempts = Column(Integer, nullable=False, server_default="0")
    engine_error = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_events_server_timestamp", "server", "timestamp_utc"),
        Index("ix_events_source_timestamp", "source", "timestamp_utc"),
        Index("ix_events_service_timestamp", "service", "timestamp_utc"),
        Index("ix_events_ip_client_timestamp", "ip_client", "timestamp_utc"),
        Index("ix_events_engine_status_created_at", "engine_status", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Event id={self.id} server={self.server} source={self.source} service={self.service}>"

