# app/jobs/job_state_utils.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.job_state import JobState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_last_run(db: Session, job_name: str, fallback_since: datetime) -> datetime:
    row = db.query(JobState).filter(JobState.job_name == job_name).first()
    if not row or not row.last_run_at:
        return fallback_since
    ts = row.last_run_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def set_last_run(db: Session, job_name: str, when: Optional[datetime] = None) -> None:
    when = when or utc_now()
    row = db.query(JobState).filter(JobState.job_name == job_name).first()
    if not row:
        row = JobState(job_name=job_name, last_run_at=when)
        db.add(row)
    else:
        row.last_run_at = when
    db.flush()


def since_with_overlap(last_run: datetime, overlap_minutes: int) -> datetime:
    if overlap_minutes <= 0:
        return last_run
    return last_run - timedelta(minutes=overlap_minutes)