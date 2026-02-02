from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from app.db import Base


class IncidentRule(Base):
    """
    Reglas para correlación de incidentes a partir de ALERTAS (no events).
    - group_by: lista de campos (de alert.evidence.group_values) para construir group_key
    - condition: expresión segura evaluada con métricas agregadas de alertas en ventana
    """
    __tablename__ = "incident_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)

    code = Column(String(64), nullable=False, unique=True)      # INC-ACC-01, etc
    name = Column(String(255), nullable=False)
    enabled = Column(Boolean, nullable=False, server_default="true")

    scope = Column(String(16), nullable=False, server_default="local")  # local/global
    severity_base = Column(Integer, nullable=False, server_default="10")
    score_bonus = Column(Integer, nullable=False, server_default="0")   # bonus al incidente

    # ventana/cooldown en segundos
    window_seconds = Column(Integer, nullable=False, server_default="1800")
    cooldown_seconds = Column(Integer, nullable=False, server_default="3600")

    # entidad principal del incidente
    primary_entity_type = Column(String(32), nullable=False)  # ip/user/host/asn/country/subnet24/server/domain
    primary_entity_field = Column(String(128), nullable=False)  # ej: "ip_client", "username", "extra.vhost", etc (pero para incidentes se lee de alert evidence)

    # filtros y lógica
    match = Column(JSONB, nullable=False, server_default="{}")      # ej: {"alert_codes_any": ["AUTH-003","MAIL-002"]}
    group_by = Column(JSONB, nullable=False, server_default="[]")   # ej: ["server","username"]
    condition = Column(Text, nullable=False, server_default="")     # ej: "count >= 1 and has_any_success == True"

    # para enriquecer / debug
    description = Column(Text, nullable=True)
    tags = Column(JSONB, nullable=False, server_default="[]")
    meta = Column(JSONB, nullable=False, server_default="{}")

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
