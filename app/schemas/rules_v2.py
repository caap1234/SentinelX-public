from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Ajusta este rango si en el futuro quieres más.
# Hoy tus datos usan hasta 30.
SEVERITY_MIN = 1
SEVERITY_MAX = 30


class RuleV2Base(BaseModel):
    name: str = Field(..., max_length=255)
    description: Optional[str] = None

    enabled: bool = True

    # ej: APACHE_ACCESS
    source: str = Field(..., max_length=64)

    # ej: http_access (canonical lower recomendado)
    event_type: str = Field(..., max_length=64)

    # ✅ Antes estaba le=10 y tu BD tiene 12/15/18/20/25/30
    severity: int = Field(3, ge=SEVERITY_MIN, le=SEVERITY_MAX)

    match: Dict[str, Any] = Field(default_factory=dict)
    group_by: List[str] = Field(default_factory=list)

    window_seconds: int = Field(300, ge=1)
    let: Dict[str, Any] = Field(default_factory=dict)
    condition: str = ""

    cooldown_seconds: int = Field(900, ge=0)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    emit: Dict[str, Any] = Field(default_factory=dict)

    tags: List[str] = Field(default_factory=list)
    version: int = Field(1, ge=1)


class RuleV2Create(RuleV2Base):
    pass


class RuleV2Update(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = None

    enabled: Optional[bool] = None

    source: Optional[str] = Field(default=None, max_length=64)
    event_type: Optional[str] = Field(default=None, max_length=64)

    # ✅ Igual que RuleV2Base
    severity: Optional[int] = Field(default=None, ge=SEVERITY_MIN, le=SEVERITY_MAX)

    match: Optional[Dict[str, Any]] = None
    group_by: Optional[List[str]] = None

    window_seconds: Optional[int] = Field(default=None, ge=1)
    let: Optional[Dict[str, Any]] = None
    condition: Optional[str] = None

    cooldown_seconds: Optional[int] = Field(default=None, ge=0)
    evidence: Optional[Dict[str, Any]] = None
    emit: Optional[Dict[str, Any]] = None

    tags: Optional[List[str]] = None
    version: Optional[int] = Field(default=None, ge=1)


class RuleV2Out(RuleV2Base):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ReprocessRequest(BaseModel):
    """
    Reprocesa reconstruyendo alerts/states para un rango.
    Si rule_id es None => reprocesa todas las reglas habilitadas (caro).
    """
    rule_id: Optional[int] = None
    server: Optional[str] = None

    # ISO8601; si no los mandas, usa un rango razonable en UI (ej: últimas 24h)
    time_min: datetime
    time_max: datetime

    # seguridad para no tumbar el server por accidente
    max_events: int = Field(200_000, ge=1, le=2_000_000)
