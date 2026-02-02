from __future__ import annotations

import csv
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.engine import Result
from sqlalchemy.orm import Session


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ExportRequest:
    # OJO: 3650 días puede ser enorme si events crece mucho.
    # Si quieres evitar OOM por defecto, baja esto (ej: 30/90/365).
    days: int = 3650

    # events, alerts, incidents, entities, api_keys, users, rules_v2, incident_rules
    include: Optional[List[str]] = None

    # filtros “audit”
    alert_dispositions: Optional[List[str]] = None
    incident_dispositions: Optional[List[str]] = None
    statuses: Optional[List[str]] = None  # open/closed/false_positive etc (si aplica)


def _safe_list(v: Any) -> List[str]:
    if not v:
        return []
    return [str(x).strip() for x in v if str(x).strip()]


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def build_export_zip(db: Session, req: ExportRequest) -> bytes:
    include = req.include or ["events", "alerts", "incidents", "entities"]
    include = [x.strip().lower() for x in include if x and str(x).strip()]

    since = _utc_now() - timedelta(days=max(1, int(req.days or 3650)))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        meta = {
            "generated_at": _utc_now().isoformat(),
            "since": since.isoformat(),
            "include": include,
            "filters": {
                "alert_dispositions": _safe_list(req.alert_dispositions),
                "incident_dispositions": _safe_list(req.incident_dispositions),
                "statuses": _safe_list(req.statuses),
            },
        }
        z.writestr("meta.json", _json(meta).encode("utf-8"))

        if "events" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="events.csv",
                sql="""
                    SELECT *
                    FROM events
                    WHERE timestamp_utc >= :since
                    ORDER BY timestamp_utc DESC
                """,
                params={"since": since},
            )

        if "alerts" in include:
            where, params = _alert_where(since, req)
            _write_query_csv_stream(
                db,
                z,
                filename="alerts.csv",
                sql=f"""
                    SELECT *
                    FROM alerts
                    WHERE {where}
                    ORDER BY triggered_at DESC
                """,
                params=params,
            )

        if "incidents" in include:
            where, params = _incident_where(since, req)
            _write_query_csv_stream(
                db,
                z,
                filename="incidents.csv",
                sql=f"""
                    SELECT *
                    FROM incidents
                    WHERE {where}
                    ORDER BY last_activity_at DESC
                """,
                params=params,
            )

        if "entities" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="entities.csv",
                sql="""
                    SELECT *
                    FROM entities
                    WHERE updated_at >= :since
                    ORDER BY updated_at DESC
                """,
                params={"since": since},
            )

        if "rules_v2" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="rules_v2.csv",
                sql="SELECT * FROM rules_v2 ORDER BY id DESC",
                params={},
            )

        if "incident_rules" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="incident_rules.csv",
                sql="SELECT * FROM incident_rules ORDER BY id DESC",
                params={},
            )

        # opcionales (si existen en tu esquema)
        if "api_keys" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="api_keys.csv",
                sql="SELECT * FROM api_keys ORDER BY id DESC",
                params={},
            )

        if "users" in include:
            _write_query_csv_stream(
                db,
                z,
                filename="users.csv",
                sql="SELECT * FROM users ORDER BY id DESC",
                params={},
            )

    return buf.getvalue()


def _write_query_csv_stream(
    db: Session,
    z: zipfile.ZipFile,
    *,
    filename: str,
    sql: str,
    params: Dict[str, Any],
    fetch_size: int = 5000,
) -> None:
    """
    Escribe un CSV dentro del ZIP en modo streaming (sin fetchall()).

    - stream_results=True pide a SQLAlchemy/driver no cargar todo en memoria.
    - fetchmany() baja el consumo y evita OOM.
    - ZipFile.open() permite escribir el archivo interno por chunks.
    """
    stmt = text(sql)

    # Importante: stream_results evita que SQLAlchemy intente materializar todo.
    res: Result = db.execute(stmt.execution_options(stream_results=True), params)

    cols = list(res.keys())

    # Escribimos como UTF-8 con BOM para Excel (utf-8-sig)
    with z.open(filename, mode="w") as zf:
        wrapper = io.TextIOWrapper(zf, encoding="utf-8-sig", newline="")
        w = csv.writer(wrapper)

        w.writerow(cols)

        while True:
            batch = res.fetchmany(fetch_size)
            if not batch:
                break
            for row in batch:
                # row puede ser Row/tuple; csv acepta secuencias
                w.writerow(list(row))

        wrapper.flush()


def _alert_where(since: datetime, req: ExportRequest) -> Tuple[str, Dict[str, Any]]:
    where = ["triggered_at >= :since"]
    params: Dict[str, Any] = {"since": since}

    disp = _safe_list(req.alert_dispositions)
    if disp:
        where.append("COALESCE(disposition,'') = ANY(:disp)")
        params["disp"] = disp

    st = _safe_list(req.statuses)
    if st:
        where.append("COALESCE(status,'') = ANY(:st)")
        params["st"] = st

    return " AND ".join(where), params


def _incident_where(since: datetime, req: ExportRequest) -> Tuple[str, Dict[str, Any]]:
    where = ["last_activity_at >= :since"]
    params: Dict[str, Any] = {"since": since}

    disp = _safe_list(req.incident_dispositions)
    if disp:
        where.append("COALESCE(disposition,'') = ANY(:disp)")
        params["disp"] = disp

    st = _safe_list(req.statuses)
    if st:
        where.append("COALESCE(status,'') = ANY(:st)")
        params["st"] = st

    return " AND ".join(where), params
