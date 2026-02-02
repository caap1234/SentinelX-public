from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.rule_v2 import RuleV2
from app.models.user import User
from app.schemas.rules_v2 import (
    RuleV2Create,
    RuleV2Out,
    RuleV2Update,
    ReprocessRequest,
)
from app.services.rule_engine_runtime import invalidate_rule_engine_cache
from app.services.rule_reprocess import reprocess_events

# Auth (JWT)
from app.routers.auth import get_current_user

router = APIRouter(prefix="/rules-v2", tags=["RulesV2"])


# -------------------------
# Admin guard
# -------------------------

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Permite acceso SOLO a usuarios admin.
    """
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user


# -------------------------
# Normalizers
# -------------------------

def _norm_source(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    return v.strip().upper()


def _norm_event_type(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    return v.strip().lower()


# -------------------------
# Routes (ADMIN ONLY)
# -------------------------

@router.get("", response_model=List[RuleV2Out])
def list_rules(
    enabled: Optional[bool] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    q = db.query(RuleV2)

    if enabled is not None:
        q = q.filter(RuleV2.enabled.is_(enabled))

    if source:
        q = q.filter(RuleV2.source == _norm_source(source))

    if event_type:
        q = q.filter(RuleV2.event_type == _norm_event_type(event_type))

    return q.order_by(RuleV2.id.desc()).all()


@router.get("/{rule_id}", response_model=RuleV2Out)
def get_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = db.query(RuleV2).filter(RuleV2.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")
    return r


@router.post("", response_model=RuleV2Out, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: RuleV2Create,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = RuleV2(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        source=_norm_source(payload.source),
        event_type=_norm_event_type(payload.event_type),
        severity=payload.severity,
        match=payload.match or {},
        group_by=payload.group_by or [],
        window_seconds=payload.window_seconds,
        let=payload.let or {},
        condition=payload.condition or "",
        cooldown_seconds=payload.cooldown_seconds,
        evidence=payload.evidence or {},
        emit=payload.emit or {},
        tags=payload.tags or [],
        version=payload.version,
    )

    db.add(r)
    db.commit()
    db.refresh(r)

    invalidate_rule_engine_cache()
    return r


@router.patch("/{rule_id}", response_model=RuleV2Out)
def update_rule(
    rule_id: int,
    payload: RuleV2Update,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = db.query(RuleV2).filter(RuleV2.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")

    data = payload.model_dump(exclude_unset=True)

    if "source" in data and data["source"] is not None:
        data["source"] = _norm_source(data["source"])

    if "event_type" in data and data["event_type"] is not None:
        data["event_type"] = _norm_event_type(data["event_type"])

    for k, v in data.items():
        setattr(r, k, v)

    db.add(r)
    db.commit()
    db.refresh(r)

    invalidate_rule_engine_cache()
    return r


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = db.query(RuleV2).filter(RuleV2.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")

    db.delete(r)
    db.commit()

    invalidate_rule_engine_cache()
    return None


@router.post("/{rule_id}/enable", response_model=RuleV2Out)
def enable_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = db.query(RuleV2).filter(RuleV2.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")

    r.enabled = True
    db.add(r)
    db.commit()
    db.refresh(r)

    invalidate_rule_engine_cache()
    return r


@router.post("/{rule_id}/disable", response_model=RuleV2Out)
def disable_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    r = db.query(RuleV2).filter(RuleV2.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rule not found")

    r.enabled = False
    db.add(r)
    db.commit()
    db.refresh(r)

    invalidate_rule_engine_cache()
    return r


@router.post("/reprocess")
def reprocess(
    payload: ReprocessRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),  # 🔒 ADMIN ONLY
):
    """
    Reconstruye alerts/states para un rango (y opcional regla/servidor).
    Operación destructiva → SOLO ADMIN.
    """
    invalidate_rule_engine_cache()
    return reprocess_events(
        db,
        time_min=payload.time_min,
        time_max=payload.time_max,
        rule_id=payload.rule_id,
        server=payload.server,
        max_events=payload.max_events,
    )
