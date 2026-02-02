from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.services.rule_engine_v2 import RuleEngineV2


_ENGINE: Optional[RuleEngineV2] = None
_LAST_RELOAD_AT: Optional[datetime] = None


def invalidate_rule_engine_cache(*, hard: bool = False) -> None:
    """
    Invalida el cache del engine para forzar recarga en el siguiente get_rule_engine().

    hard=False: mantiene el engine (estado in-memory) y solo fuerza reload_rules().
    hard=True: reinicia el engine por completo (pierde estado in-memory).
    """
    global _ENGINE, _LAST_RELOAD_AT
    _LAST_RELOAD_AT = None
    if hard:
        _ENGINE = None


def get_rule_engine() -> RuleEngineV2:
    """
    Singleton por proceso.

    - NO guarda una Session externa (Session no es thread-safe).
    - Para recargar reglas con TTL, abre una sesión corta interna.
    """
    global _ENGINE, _LAST_RELOAD_AT

    if _ENGINE is None:
        _ENGINE = RuleEngineV2()

    ttl_seconds = int(os.getenv("RULES_RELOAD_SECONDS", "30").strip() or "30")
    now = datetime.now(timezone.utc)

    if _LAST_RELOAD_AT is None or (now - _LAST_RELOAD_AT) >= timedelta(seconds=ttl_seconds):
        db: Session = SessionLocal()
        try:
            _ENGINE.reload_rules(db)
            _LAST_RELOAD_AT = now
        finally:
            db.close()

    return _ENGINE
