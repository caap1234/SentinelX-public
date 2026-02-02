# app/models/raw_log.py
from __future__ import annotations

from sqlalchemy import BigInteger, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base


class RawLog(Base):
    __tablename__ = "rawlogs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    server = Column(String(255), nullable=False, index=True)
    source_hint = Column(String(64), nullable=False, index=True)

    # texto completo de la línea
    raw = Column(Text, nullable=False)

    # opcionales
    log_upload_id = Column(
        Integer,
        ForeignKey("log_uploads.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    line_no = Column(Integer, nullable=True)

    extra = Column(JSONB, nullable=False, server_default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Relación inversa: un raw puede referenciarse por muchos events (normalmente 1:1, pero no lo fuerces)
    events = relationship("Event", back_populates="rawlog", passive_deletes=True)

    def __repr__(self) -> str:
        return f"<RawLog id={self.id} server={self.server} source_hint={self.source_hint}>"
