from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.incident_rule import IncidentRule
from app.models.user import User
from app.routers.auth import get_current_user
from app.schemas.incident_rules import IncidentRuleCreate, IncidentRuleOut, IncidentRuleUpdate


router = APIRouter(prefix="/incident-rules", tags=["IncidentRules"])


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


@router.get("", response_model=List[IncidentRuleOut])
def list_incident_rules(
    enabled: Optional[bool] = None,
    scope: Optional[str] = None,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    q = db.query(IncidentRule)
    if enabled is not None:
        q = q.filter(IncidentRule.enabled.is_(enabled))
    if scope:
        q = q.filter(IncidentRule.scope == scope.strip().lower())
    return q.order_by(IncidentRule.id.desc()).all()


@router.get("/{rule_id}", response_model=IncidentRuleOut)
def get_incident_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    r = db.query(IncidentRule).filter(IncidentRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="IncidentRule not found")
    return r


@router.post("", response_model=IncidentRuleOut, status_code=status.HTTP_201_CREATED)
def create_incident_rule(
    payload: IncidentRuleCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    exists = db.query(IncidentRule).filter(IncidentRule.code == payload.code).first()
    if exists:
        raise HTTPException(status_code=409, detail="code already exists")

    r = IncidentRule(
        code=payload.code.strip().upper(),
        name=payload.name.strip(),
        enabled=bool(payload.enabled),
        scope=payload.scope.strip().lower(),
        severity_base=int(payload.severity_base),
        score_bonus=int(payload.score_bonus),
        window_seconds=int(payload.window_seconds),
        cooldown_seconds=int(payload.cooldown_seconds),
        primary_entity_type=payload.primary_entity_type.strip().lower(),
        primary_entity_field=payload.primary_entity_field.strip(),
        match=payload.match or {},
        group_by=payload.group_by or [],
        condition=payload.condition or "",
        description=payload.description,
        tags=payload.tags or [],
        meta=payload.meta or {},
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@router.patch("/{rule_id}", response_model=IncidentRuleOut)
def update_incident_rule(
    rule_id: int,
    payload: IncidentRuleUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    r = db.query(IncidentRule).filter(IncidentRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="IncidentRule not found")

    data = payload.model_dump(exclude_unset=True)

    if "code" in data and data["code"]:
        data["code"] = str(data["code"]).strip().upper()

    if "scope" in data and data["scope"]:
        data["scope"] = str(data["scope"]).strip().lower()

    if "primary_entity_type" in data and data["primary_entity_type"]:
        data["primary_entity_type"] = str(data["primary_entity_type"]).strip().lower()

    for k, v in data.items():
        setattr(r, k, v)

    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    r = db.query(IncidentRule).filter(IncidentRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="IncidentRule not found")
    db.delete(r)
    db.commit()
    return None


@router.post("/{rule_id}/enable", response_model=IncidentRuleOut)
def enable_incident_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    r = db.query(IncidentRule).filter(IncidentRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="IncidentRule not found")
    r.enabled = True
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


@router.post("/{rule_id}/disable", response_model=IncidentRuleOut)
def disable_incident_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    r = db.query(IncidentRule).filter(IncidentRule.id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="IncidentRule not found")
    r.enabled = False
    db.add(r)
    db.commit()
    db.refresh(r)
    return r
