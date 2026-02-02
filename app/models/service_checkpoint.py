# app/models/service_checkpoint.py
from __future__ import annotations

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict

from app.db import Base


class ServiceCheckpoint(Base):
    """
    Guarda checkpoints para jobs (cron) idempotentes:
      - name: "incidents_job", "entities_job"
      - last_run_at: timestamp UTC
      - meta: JSON opcional

    IMPORTANTE:
      JSONB por defecto NO trackea mutaciones in-place.
      Usamos MutableDict para que los cambios en meta se persistan correctamente.
    """
    __tablename__ = "service_checkpoints"

    name = Column(String(64), primary_key=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)

    meta = Column(MutableDict.as_mutable(JSONB), nullable=False, server_default="{}")

