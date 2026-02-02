from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IncidentRuleBase(BaseModel):
    code: str = Field(..., max_length=64)
    name: str = Field(..., max_length=255)
    enabled: bool = True

    scope: str = Field("local", max_length=16)  # local/global
    severity_base: int = Field(10, ge=0, le=100)
    score_bonus: int = Field(0, ge=-100, le=100)

    window_seconds: int = Field(1800, ge=1)
    cooldown_seconds: int = Field(3600, ge=0)

    primary_entity_type: str = Field(..., max_length=32)
    primary_entity_field: str = Field(..., max_length=128)

    match: Dict[str, Any] = Field(default_factory=dict)
    group_by: List[str] = Field(default_factory=list)
    condition: str = ""

    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    meta: Dict[str, Any] = Field(default_factory=dict)


class IncidentRuleCreate(IncidentRuleBase):
    pass


class IncidentRuleUpdate(BaseModel):
    code: Optional[str] = Field(default=None, max_length=64)
    name: Optional[str] = Field(default=None, max_length=255)
    enabled: Optional[bool] = None

    scope: Optional[str] = Field(default=None, max_length=16)
    severity_base: Optional[int] = Field(default=None, ge=0, le=100)
    score_bonus: Optional[int] = Field(default=None, ge=-100, le=100)

    window_seconds: Optional[int] = Field(default=None, ge=1)
    cooldown_seconds: Optional[int] = Field(default=None, ge=0)

    primary_entity_type: Optional[str] = Field(default=None, max_length=32)
    primary_entity_field: Optional[str] = Field(default=None, max_length=128)

    match: Optional[Dict[str, Any]] = None
    group_by: Optional[List[str]] = None
    condition: Optional[str] = None

    description: Optional[str] = None
    tags: Optional[List[str]] = None
    meta: Optional[Dict[str, Any]] = None


class IncidentRuleOut(IncidentRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
