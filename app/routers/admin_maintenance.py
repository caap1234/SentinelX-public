from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from typing import List, Optional, Set

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.services.exporter import ExportRequest, build_export_zip

router = APIRouter(prefix="/admin/maintenance", tags=["AdminMaintenance"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


def _uploaded_logs_dir() -> str:
    """
    Resuelve la carpeta de uploaded logs.
    Prioridad:
      1) UPLOADED_LOGS_DIR (env)
      2) /app/app/uploaded_logs  (lo típico si el repo está en /app y la carpeta vive dentro de app/)
      3) /app/uploaded_logs
      4) ./app/uploaded_logs (relativo al CWD)
    """
    env = (os.getenv("UPLOADED_LOGS_DIR") or "").strip()
    candidates = [
        env.rstrip("/") if env else "",
        "/app/app/uploaded_logs",
        "/app/uploaded_logs",
        os.path.abspath(os.path.join(os.getcwd(), "app", "uploaded_logs")),
    ]

    for c in candidates:
        if c and os.path.isdir(c):
            return c.rstrip("/")

    # último fallback: aunque no exista, devolvemos el que más probablemente es correcto en docker
    return "/app/app/uploaded_logs"


class CleanResult(BaseModel):
    removed_files: int = 0
    removed_dirs: int = 0
    errors: List[str] = Field(default_factory=list)


def _count_files_recursive(path: str) -> int:
    total = 0
    for _root, _dirs, files in os.walk(path):
        total += len(files)
    return total


@router.post("/clean-uploaded-logs", response_model=CleanResult)
def clean_uploaded_logs(
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> CleanResult:
    base = _uploaded_logs_dir()
    if not os.path.isdir(base):
        return CleanResult(removed_files=0, removed_dirs=0, errors=[f"Base dir not found: {base}"])

    result = CleanResult()

    # Borramos TODO lo que esté dentro de base, pero preservamos la carpeta base.
    try:
        entries = list(os.scandir(base))
    except Exception as e:
        return CleanResult(removed_files=0, removed_dirs=0, errors=[f"Cannot scan base dir {base}: {e}"])

    for entry in entries:
        p = entry.path
        try:
            if entry.is_symlink():
                # si es symlink, lo eliminamos como archivo
                os.unlink(p)
                result.removed_files += 1
                continue

            if entry.is_file():
                os.remove(p)
                result.removed_files += 1
                continue

            if entry.is_dir():
                # contamos antes para reportar
                result.removed_files += _count_files_recursive(p)
                shutil.rmtree(p)
                result.removed_dirs += 1
                continue

            # otros tipos (fifo, socket, etc.)
            os.remove(p)
            result.removed_files += 1

        except Exception as e:
            result.errors.append(f"Failed to remove {p}: {e}")

    return result


class ExportPayload(BaseModel):
    days: int = Field(3650, ge=1, le=3650)
    include: List[str] = Field(default_factory=lambda: ["events", "alerts", "incidents", "entities"])
    alert_dispositions: Optional[List[str]] = None
    incident_dispositions: Optional[List[str]] = None
    statuses: Optional[List[str]] = None


@router.post("/export.zip")
def export_zip(
    payload: ExportPayload,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
):
    data = build_export_zip(
        db,
        ExportRequest(
            days=payload.days,
            include=[x.lower().strip() for x in (payload.include or []) if str(x).strip()],
            alert_dispositions=payload.alert_dispositions,
            incident_dispositions=payload.incident_dispositions,
            statuses=payload.statuses,
        ),
    )
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="sentinelx_export.zip"'},
    )


class BackupWipePayload(BaseModel):
    export_days: int = Field(3650, ge=1, le=3650)


class BackupWipeResult(BaseModel):
    backup_path: str
    wiped_tables_count: int


@router.post("/backup-and-wipe-db", response_model=BackupWipeResult)
def backup_and_wipe_db(
    payload: BackupWipePayload,
    db: Session = Depends(get_db),
    _: User = Depends(require_admin),
) -> BackupWipeResult:
    # 1) genera ZIP
    data = build_export_zip(
        db,
        ExportRequest(
            days=int(payload.export_days),
            include=["events", "alerts", "incidents", "entities", "rules_v2", "incident_rules"],
        ),
    )

    backups_dir = (os.getenv("BACKUPS_DIR") or "/app/backups").rstrip("/")
    os.makedirs(backups_dir, exist_ok=True)
    name = f"sentinelx_backup_{_utc_now().strftime('%Y%m%d_%H%M%S')}.zip"
    path = os.path.join(backups_dir, name)

    with open(path, "wb") as f:
        f.write(data)

    # 2) wipe: TRUNCATE todo excepto:
    # - Alembic
    # - auth/user tables
    # - settings
    # - reglas y su estado (rules_v2, rule_states_v2, incident_rules, incident_rule_state)
    keep: Set[str] = {
        "alembic_version",
        "users",
        "api_keys",
        "user_settings",
        "system_settings",
        # Rules V2
        "rules_v2",
        "rule_states_v2",
        # Incident rules (según lo que pediste)
        "incident_rules",
        "incident_rule_state",
        # variante común en plural (por si tu tabla está así)
        "incident_rule_states",
    }

    insp = inspect(db.bind)
    tables = [t for t in insp.get_table_names() if t not in keep]

    if tables:
        sql = "TRUNCATE " + ", ".join([f'"{t}"' for t in tables]) + " RESTART IDENTITY CASCADE"
        db.execute(text(sql))
        db.commit()

    return BackupWipeResult(backup_path=path, wiped_tables_count=int(len(tables)))
