# app/models/job_state.py
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Index
from app.db import Base


class JobState(Base):
    __tablename__ = "job_state"

    id = Column(Integer, primary_key=True)
    job_name = Column(String(128), nullable=False, unique=True, index=True)

    last_run_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    __table_args__ = (
        Index("ix_job_state_job_name", "job_name"),
    )
