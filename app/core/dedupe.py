from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional


def _to_utc_iso(ts: Optional[datetime]) -> str:
    if not ts:
        return ""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        ts = ts.astimezone(timezone.utc)
    return ts.replace(microsecond=0).isoformat()


def compute_fingerprint(
    *,
    server: str,
    source: str,
    service: str,
    rule_id: str,
    timestamp_utc: Optional[datetime],
    ip_client: Optional[str] = None,
    domain: Optional[str] = None,
    username: Optional[str] = None,
    message: str,
) -> str:
    payload = "|".join(
        [
            (server or "").strip(),
            (source or "").strip(),
            (service or "").strip(),
            (rule_id or "").strip(),
            _to_utc_iso(timestamp_utc),
            (ip_client or "").strip(),
            (domain or "").strip().lower(),
            (username or "").strip().lower(),
            (message or "").strip(),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
