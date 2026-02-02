from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user_setting import UserSetting
from app.routers.auth import get_current_user  # type: ignore

router = APIRouter(prefix="/settings", tags=["Settings"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_user_setting(db: Session, *, user_id: int, key: str) -> Optional[UserSetting]:
    return (
        db.query(UserSetting)
        .filter(UserSetting.user_id == int(user_id), UserSetting.key == key)
        .first()
    )


def _defaults_alert_email() -> Dict[str, Any]:
    return {"high": True, "medium": True, "low": True, "to_email": None}


class AlertEmailSetting(BaseModel):
    high: bool = True
    medium: bool = True
    low: bool = True
    to_email: Optional[str] = Field(default=None, max_length=255)


@router.get("/alert-email", response_model=AlertEmailSetting)
def get_alert_email_setting(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AlertEmailSetting:
    uid = int(getattr(current_user, "id"))
    row = _get_user_setting(db, user_id=uid, key="alert_email")

    if not row or not (row.value or "").strip():
        return AlertEmailSetting(**_defaults_alert_email())

    try:
        data = json.loads(row.value)
        if not isinstance(data, dict):
            raise ValueError("not dict")
    except Exception:
        # si quedó basura en DB, regresamos default sin reventar
        return AlertEmailSetting(**_defaults_alert_email())

    out = _defaults_alert_email()
    out["high"] = bool(data.get("high", True))
    out["medium"] = bool(data.get("medium", True))
    out["low"] = bool(data.get("low", True))
    out["to_email"] = (str(data.get("to_email")).strip() if data.get("to_email") else None)

    return AlertEmailSetting(**out)


@router.put("/alert-email", response_model=AlertEmailSetting)
def put_alert_email_setting(
    payload: AlertEmailSetting,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AlertEmailSetting:
    uid = int(getattr(current_user, "id"))

    to_email = payload.to_email.strip() if payload.to_email else None
    if to_email and not EMAIL_RE.match(to_email):
        raise HTTPException(status_code=422, detail="Invalid to_email")

    data: Dict[str, Any] = {
        "high": bool(payload.high),
        "medium": bool(payload.medium),
        "low": bool(payload.low),
        "to_email": to_email,
    }

    row = _get_user_setting(db, user_id=uid, key="alert_email")
    if not row:
        row = UserSetting(user_id=uid, key="alert_email", value=json.dumps(data))
    else:
        row.value = json.dumps(data)
    row.updated_at = _utc_now()

    db.add(row)
    db.commit()
    db.refresh(row)

    return AlertEmailSetting(**data)
