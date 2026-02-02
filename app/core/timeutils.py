# app/core/timeutils.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from zoneinfo import ZoneInfo

# Ajusta a la zona horaria real de tus servidores
SERVER_TZ = ZoneInfo("America/Mexico_City")


def _try_parse_with_formats(value: str, fmts: List[str]) -> Optional[datetime]:
    for fmt in fmts:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _normalize_spaces(value: str) -> str:
    # Reduce espacios múltiples a uno (Apache error a veces trae doble espacio en el día)
    # Ej: "Tue Oct  7 06:27:41 2025" -> "Tue Oct 7 06:27:41 2025"
    return " ".join((value or "").strip().split())


def parse_any_timestamp_to_utc(value: str) -> datetime:
    """
    Intenta parsear un timestamp en formatos típicos de logs (Apache, PHP/WP, syslog)
    y devolverlo en UTC usando solo la librería estándar.
    Si no se puede parsear, retorna "ahora" UTC (fallback), pero tratando de reducir falsos positivos
    primero con normalización.
    """
    value = (value or "").strip()
    if not value:
        return datetime.now(timezone.utc)

    # 1) Si viene con brackets: [10/Dec/2025:14:23:00 +0000]
    if value[0] == "[" and value[-1] == "]":
        value = value[1:-1].strip()

    # Normalización útil para Apache error y syslog (dobles espacios)
    norm = _normalize_spaces(value)

    # ---- 1) Intentos con zona incluida ----
    dt = _try_parse_with_formats(
        norm,
        [
            "%d/%b/%Y:%H:%M:%S %z",   # Apache access: 10/Dec/2025:14:23:00 +0000
            "%Y-%m-%d %H:%M:%S%z",    # 2025-12-06 15:20:01+0000
            "%Y-%m-%d %H:%M:%S %z",   # 2025-12-06 15:20:01 +0000
        ],
    )
    if dt:
        return dt.astimezone(timezone.utc)

    # ---- 2) Formatos tipo Apache error log (SIN zona) ----
    # Ej: "Tue Oct 21 06:27:41.257881 2025"
    # Ej: "Tue Oct 21 06:27:41 2025"
    dt = _try_parse_with_formats(
        norm,
        [
            "%a %b %d %H:%M:%S.%f %Y",
            "%a %b %d %H:%M:%S %Y",
        ],
    )
    if dt:
        dt_local = dt.replace(tzinfo=SERVER_TZ)
        return dt_local.astimezone(timezone.utc)

    # ---- 3) Formatos con fecha completa pero SIN zona ----
    dt = _try_parse_with_formats(
        norm,
        [
            "%Y-%m-%d %H:%M:%S",      # 2025-12-06 15:20:01
            "%d/%b/%Y:%H:%M:%S",      # 10/Dec/2025:14:23:00
            "%d-%b-%Y %H:%M:%S",      # 10-Dec-2025 14:23:00
        ],
    )
    if dt:
        dt_local = dt.replace(tzinfo=SERVER_TZ)
        return dt_local.astimezone(timezone.utc)

    # ---- 4) Formato syslog sin año: "Dec 11 11:26:23" ----
    dt = _try_parse_with_formats(
        norm,
        [
            "%b %d %H:%M:%S",   # Dec 11 11:26:23
        ],
    )
    if dt:
        from datetime import timedelta

        now_local = datetime.now(SERVER_TZ)
        dt_local = dt.replace(year=now_local.year, tzinfo=SERVER_TZ)

        # Si quedó "en el futuro" (ej. corriendo en enero y el log es diciembre del año anterior),
        # corrige restando 1 año.
        if dt_local > (now_local + timedelta(days=1)):
            dt_local = dt_local.replace(year=dt_local.year - 1)

        return dt_local.astimezone(timezone.utc)

    # ---- 5) Fallback ----
    return datetime.now(timezone.utc)
