# app/core/models.py
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, validator

from .enums import (
    Severity,
    CorrelationScope,
    LogSource,
    Service,
    SeverityLevel,
    SEVERITY_INT_TO_ENUM,
)


class RawEvent(BaseModel):
    """
    Evento “bruto” parseado de una línea de log,
    antes de aplicar reglas de detección/correlación.
    """
    timestamp_utc: datetime
    server: str
    source: LogSource
    ip_client: Optional[str] = None
    ip_server: Optional[str] = None
    domain: Optional[str] = None
    user: Optional[str] = None
    service: Service = Service.UNKNOWN
    message: str
    raw: str
    extra: Dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    """
    Evento detectado / correlacionado según reglas SentinelX.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp_utc: datetime
    server: str
    source: LogSource
    ip_client: Optional[str] = None
    ip_server: Optional[str] = None
    domain: Optional[str] = None
    user: Optional[str] = None
    service: Service = Service.UNKNOWN

    rule_id: Optional[str] = None      # A1, W3, WP1, X3, MS5, etc.
    rule_name: Optional[str] = None

    # ✅ default para evitar que te obligue siempre a setearlo
    severity: Severity = Severity.LOW
    correlation_scope: CorrelationScope = CorrelationScope.LOCAL

    message: str
    extra: Dict[str, Any] = Field(default_factory=dict)

    @validator("severity", pre=True)
    def _normalize_severity(cls, v):
        """
        Acepta:
          - Severity enum (LOW/MEDIUM/HIGH/CRITICAL)
          - string ("low", "HIGH", "crit", etc.)
          - int de DB (0..4) y lo convierte al enum string
        """
        if v is None:
            return Severity.LOW

        # ya es enum
        if isinstance(v, Severity):
            return v

        # int -> enum (0=info lo mapeamos a LOW)
        if isinstance(v, int):
            if v == SeverityLevel.INFO:
                return Severity.LOW
            return SEVERITY_INT_TO_ENUM.get(v, Severity.MEDIUM)

        # string -> enum
        s = str(v).strip().lower()
        if s in ("critical", "crit", "crítica", "critica"):
            return Severity.CRITICAL
        if s in ("high", "alta"):
            return Severity.HIGH
        if s in ("medium", "media"):
            return Severity.MEDIUM
        if s in ("low", "baja", "info", "informational"):
            return Severity.LOW

        return Severity.LOW
