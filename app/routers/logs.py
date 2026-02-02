# app/routers/logs.py
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import (
    APIRouter,
    Depends,
    UploadFile,
    File,
    Form,
    HTTPException,
    Query,
    BackgroundTasks,
    Header,
)
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.log_upload import LogUpload
from app.models.user import User
from app.models.api_key import ApiKey
from app.routers.auth import get_current_user
from app.core.security import verify_api_key
from app.services.log_pipeline import process_log_file  # ✅ v2: pipeline en services

router = APIRouter(prefix="/logs", tags=["logs"])

UPLOAD_DIR = Path(__file__).resolve().parents[1] / "uploaded_logs"

MAX_UPLOAD_BYTES = int(
    os.getenv("MAX_UPLOAD_BYTES", 1024 * 1024 * 1024)  # 1GB default
)

CHUNK_SIZE = 1024 * 1024  # 1MB

# Tags soportados (UI/Agents) -> log_type (pipeline)
TAG_TO_LOG_TYPE = {
    # HTTP (Apache/Nginx)
    "access_log": "apache_access",
    "apache_access": "apache_access",
    "apache": "apache_access",
    "apache_error": "apache_error",
    "apache_error_log": "apache_error",

    # Nginx access (domlogs /var/log/nginx/domains/*)
    "nginx_access": "nginx_access",
    "nginx": "nginx_access",
    "nginx_domlogs": "nginx_access",
    "nginx_domains": "nginx_access",

    # Mail
    "exim_mainlog": "exim_mainlog",
    "exim": "exim_mainlog",

    # maillog (dovecot syslog) -> MaillogDovecotParser
    "maillog": "maillog",
    "dovecot": "maillog",

    # WordPress / App
    "wp_error_log": "wp_error_log",
    "wp": "wp_error_log",

    # WAF / Security
    "modsec": "modsec",
    "secure": "secure",
    "lfd": "lfd",
    "lfd_log": "lfd",

    # System
    "system": "system",
    "messages": "system",

    # Panel
    "cpanel": "cpanel_access",
    "cpanel_access": "cpanel_access",
    "panel_logs": "panel_logs",
    "login_log": "panel_logs",

    # Metrics
    "sar": "sar",
}

def _safe_lower(s: str) -> str:
    return (s or "").strip().lower()

def _guess_log_type_from_filename(filename: str) -> Optional[str]:
    """
    Fallback suave para evitar errores operativos:
    - nginx domlogs suelen traer sufijo: -ssl_log / _log en /var/log/nginx/domains/
    - maillog suele llamarse: maillog, maillog.1, maillog-YYYYMMDD, etc.
    """
    name = _safe_lower(filename)

    # Nginx domain logs comunes en DirectAdmin/Ubuntu: domain.com-ssl_log / domain.com_log
    if name.endswith(("-ssl_log", "_log")):
        return "nginx_access"

    # maillog
    if name.startswith("maillog"):
        return "maillog"

    return None


def _resolve_log_type_from_tag(tag: str, *, filename: Optional[str] = None) -> str:
    """
    Resuelve log_type con prioridad:
    1) tag explícito
    2) fallback por filename (si tag es ambiguo o no existe)
    """
    tag_norm = _safe_lower(tag)
    log_type = TAG_TO_LOG_TYPE.get(tag_norm)

    if not log_type and filename:
        guessed = _guess_log_type_from_filename(filename)
        if guessed:
            log_type = guessed

    if not log_type:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Etiqueta/tag de log no soportada: '{tag}'. "
                f"Tags soportados: {', '.join(sorted(TAG_TO_LOG_TYPE.keys()))}"
            ),
        )
    return log_type


def _safe_filename(name: str) -> str:
    name = (name or "upload.log").strip()
    name = name.replace("/", "_").replace("\\", "_")
    return name or "upload.log"


async def _save_upload_file_streaming(dest_path: Path, file: UploadFile) -> int:
    """
    Guarda UploadFile a disco por chunks (async). Regresa size_bytes.
    """
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    try:
        with dest_path.open("wb") as out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Archivo demasiado grande (max {MAX_UPLOAD_BYTES} bytes)",
                    )
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"No se pudo guardar archivo: {e}")
    finally:
        try:
            await file.close()
        except Exception:
            pass

    return total


def _get_api_key_record(db: Session, api_key_plain: str) -> ApiKey:
    """
    Valida X-API-Key contra la tabla api_keys (hashed_key).
    Con pocas keys, recorrer activas es OK.
    """
    api_key_plain = (api_key_plain or "").strip()
    if not api_key_plain:
        raise HTTPException(status_code=401, detail="Falta X-API-Key")

    keys: List[ApiKey] = db.query(ApiKey).filter(ApiKey.is_active.is_(True)).all()
    for k in keys:
        if not getattr(k, "hashed_key", None):
            continue
        if verify_api_key(api_key_plain, k.hashed_key):
            k.last_used_at = datetime.utcnow()
            db.commit()
            db.refresh(k)
            return k

    raise HTTPException(status_code=401, detail="API Key inválida o inactiva")


# -------------------------------------------------------------------
# 1) CARGA MANUAL (JWT) - PANEL
# -------------------------------------------------------------------
@router.post("/upload")
async def upload_log(
    background_tasks: BackgroundTasks,
    server: str = Form(...),
    tag: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    server = (server or "").strip()
    tag = (tag or "").strip()

    if not server or not tag:
        raise HTTPException(status_code=400, detail="Servidor y etiqueta son obligatorios")

    original_name = _safe_filename(file.filename or "upload.log")
    log_type = _resolve_log_type_from_tag(tag, filename=original_name)

    dest_dir = UPLOAD_DIR / server
    dest_path = dest_dir / original_name

    status = "uploaded"
    err_msg = None
    size_bytes = 0

    try:
        size_bytes = await _save_upload_file_streaming(dest_path, file)
    except HTTPException as e:
        status = "error"
        err_msg = str(e.detail)
    except Exception as e:
        status = "error"
        err_msg = f"No se pudo guardar el archivo: {e}"

    log = LogUpload(
        filename=original_name,
        server=server,
        tag=tag,
        path=str(dest_path),
        size_bytes=size_bytes,
        status=status,
        uploader_type="user",
        user_id=current_user.id,
        api_key_id=None,
        error_message=err_msg,
        extra_meta={"source": "panel", "log_type": log_type},
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    if status == "uploaded":
        log.status = "queued"
        db.commit()

    return {"id": log.id, "status": log.status, "log_type": log_type}


# -------------------------------------------------------------------
# 2) INGESTA DESDE SERVIDOR (API KEY)
# -------------------------------------------------------------------
@router.post("/ingest")
async def ingest_log(
    background_tasks: BackgroundTasks,
    tag: str = Form(...),
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db),
):
    tag = (tag or "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="Etiqueta/tag es obligatoria")

    api_key = _get_api_key_record(db, x_api_key or "")
    server = (getattr(api_key, "server", "") or "").strip()
    if not server:
        raise HTTPException(status_code=400, detail="ApiKey no tiene server asociado")

    original_name = _safe_filename(file.filename or "ingest.log")
    log_type = _resolve_log_type_from_tag(tag, filename=original_name)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}__{original_name}"

    dest_dir = UPLOAD_DIR / server
    dest_path = dest_dir / safe_name

    status = "uploaded"
    err_msg = None
    size_bytes = 0

    try:
        size_bytes = await _save_upload_file_streaming(dest_path, file)
    except HTTPException as e:
        status = "error"
        err_msg = str(e.detail)
    except Exception as e:
        status = "error"
        err_msg = f"No se pudo guardar el archivo: {e}"

    log = LogUpload(
        filename=safe_name,
        server=server,
        tag=tag,
        path=str(dest_path),
        size_bytes=size_bytes,
        status=status,
        uploader_type="api_key",
        user_id=None,
        api_key_id=api_key.id,
        error_message=err_msg,
        extra_meta={"source": "ingest", "api_key_name": getattr(api_key, "name", None), "log_type": log_type},
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    if status == "uploaded":
        log.status = "queued"
        db.commit()

    return {"id": log.id, "status": log.status, "server": server, "log_type": log_type}


# -------------------------------------------------------------------
# 3) HISTORIAL DE CARGAS
# -------------------------------------------------------------------
@router.get("/uploads")
def list_log_uploads(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
    server: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """
    Historial de cargas.
    - Admin: ve todas.
    - No admin: ve solo las suyas (uploader_type=user y user_id=...).
    """
    q = db.query(LogUpload)

    if not getattr(current_user, "is_admin", False):
        q = q.filter(LogUpload.uploader_type == "user", LogUpload.user_id == current_user.id)

    if server and server != "all":
        q = q.filter(LogUpload.server == server)

    if status and status != "all":
        q = q.filter(LogUpload.status == status)

    q = q.order_by(LogUpload.uploaded_at.desc())

    total = q.count()
    items: List[LogUpload] = q.offset(offset).limit(limit).all()

    def _dt(v):
        if isinstance(v, datetime):
            return v.isoformat()
        return str(v)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": log.id,
                "filename": log.filename,
                "server": log.server,
                "tag": log.tag,
                "status": log.status,
                "size_bytes": log.size_bytes,
                "uploaded_at": _dt(log.uploaded_at),
                "uploader_type": getattr(log, "uploader_type", None),
                "user_id": getattr(log, "user_id", None),
                "api_key_id": getattr(log, "api_key_id", None),
                "error_message": getattr(log, "error_message", None),
                "extra_meta": getattr(log, "extra_meta", None),
            }
            for log in items
        ],
    }

