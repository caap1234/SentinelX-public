from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, String, DateTime

from app.db import Base


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(191), primary_key=True, nullable=False)
    value = Column(String, nullable=False, default="")

    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
