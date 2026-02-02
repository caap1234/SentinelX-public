# app/services/system_settings_service.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.system_setting import SystemSetting


@dataclass
class CachedValue:
    value: Optional[str]
    expires_at: float


class SystemSettingsService:
    """
    Lectura/Escritura con cache (por proceso) para evitar golpear DB en loops.
    Cache por default: 5s.
    """
    def __init__(self, ttl_seconds: int = 5) -> None:
        self.ttl_seconds = int(ttl_seconds)
        self._cache: Dict[str, CachedValue] = {}

    def _now(self) -> float:
        return time.time()

    def _get_raw_uncached(self, db: Session, key: str) -> Optional[str]:
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        return row.value if row else None

    def get_raw(self, db: Session, key: str, default: Optional[str] = None) -> str:
        k = (key or "").strip()
        if not k:
            return default or ""

        now = self._now()
        cv = self._cache.get(k)
        if cv and cv.expires_at >= now:
            return cv.value if cv.value is not None else (default or "")

        v = self._get_raw_uncached(db, k)
        self._cache[k] = CachedValue(value=v, expires_at=now + self.ttl_seconds)
        return v if v is not None else (default or "")

    def get_bool(self, db: Session, key: str, default: bool = False) -> bool:
        raw = self.get_raw(db, key, default="1" if default else "0").strip().lower()
        return raw in ("1", "true", "yes", "y", "on", "enabled")

    def get_int(self, db: Session, key: str, default: int) -> int:
        raw = self.get_raw(db, key, default=str(default)).strip()
        try:
            return int(raw)
        except Exception:
            return int(default)

    def set_raw(self, db: Session, key: str, value: str) -> None:
        k = (key or "").strip()
        if not k:
            return
        v = "" if value is None else str(value)

        row = db.query(SystemSetting).filter(SystemSetting.key == k).first()
        if not row:
            row = SystemSetting(key=k, value=v)
            db.add(row)
        else:
            row.value = v

        db.commit()

        # invalida cache local
        self._cache.pop(k, None)

    def set_many(self, db: Session, updates: Dict[str, Any]) -> None:
        if not isinstance(updates, dict) or not updates:
            return
        for k, v in updates.items():
            kk = (k or "").strip()
            if not kk:
                continue
            vv = "" if v is None else str(v)

            row = db.query(SystemSetting).filter(SystemSetting.key == kk).first()
            if not row:
                row = SystemSetting(key=kk, value=vv)
                db.add(row)
            else:
                row.value = vv

            self._cache.pop(kk, None)

        db.commit()
