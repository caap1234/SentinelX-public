# app/parsing/types.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ParsedEvent:
    timestamp_utc: datetime
    server: str
    source: str
    service: str
    message: str

    ip_client: Optional[str] = None
    ip_server: Optional[str] = None
    domain: Optional[str] = None
    username: Optional[str] = None

    extra: Dict[str, Any] = field(default_factory=dict)

    log_upload_id: Optional[int] = None

    # Nuevo: referencia a rawlogs
    raw_id: Optional[int] = None

    def to_orm_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "server": self.server,
            "source": self.source,
            "service": self.service,
            "ip_client": self.ip_client,
            "ip_server": self.ip_server,
            "domain": self.domain,
            "username": self.username,
            "message": self.message,
            "extra": self.extra or {},
            "log_upload_id": self.log_upload_id,
            "raw_id": self.raw_id,
        }
