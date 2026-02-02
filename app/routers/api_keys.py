# app/routers/api_keys.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.models.api_key import ApiKey
from app.routers.auth import get_current_user
from app.core.security import generate_api_key, hash_api_key

router = APIRouter(prefix="/api-keys", tags=["api_keys"])


# ---------------------------
# Schemas
# ---------------------------

class ApiKeyCreateIn(BaseModel):
    server: str = Field(..., min_length=1, max_length=255)
    name: str = Field(..., min_length=1, max_length=255)


class ApiKeyCreateOut(BaseModel):
    id: int
    name: str
    server: str
    api_key: str  # SOLO se devuelve una vez
    is_active: bool
    created_at: Optional[str] = None


class ApiKeyListItem(BaseModel):
    id: int
    name: str
    server: str
    is_active: bool
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    created_by_user_id: Optional[int] = None


# ---------------------------
# Helpers
# ---------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _dt(v) -> Optional[str]:
    if not v:
        return None
    if isinstance(v, datetime):
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc).isoformat()
        return v.astimezone(timezone.utc).isoformat()
    return str(v)


def _require_admin(current_user: User):
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="No autorizado (solo admin).")


def _get_api_key_or_404(db: Session, api_key_id: int) -> ApiKey:
    rec = db.query(ApiKey).filter(ApiKey.id == api_key_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="API Key no encontrada")
    return rec


# ---------------------------
# Endpoints
# ---------------------------

@router.post("", response_model=ApiKeyCreateOut)
def create_api_key(
    payload: ApiKeyCreateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Crea una API Key para un servidor.
    - Guarda SOLO el hash (HMAC) en BD (ApiKey.hashed_key).
    - Devuelve api_key en texto plano SOLO una vez.
    """
    _require_admin(current_user)

    server = (payload.server or "").strip()
    name = (payload.name or "").strip()

    if not server:
        raise HTTPException(status_code=400, detail="server es obligatorio")
    if not name:
        raise HTTPException(status_code=400, detail="name es obligatorio")

    api_key_plain, _public_id = generate_api_key()
    secret_hash = hash_api_key(api_key_plain)

    rec = ApiKey(
        name=name,
        server=server,
        hashed_key=secret_hash,
        is_active=True,
        created_at=_utc_now(),
        last_used_at=None,
        created_by_user_id=getattr(current_user, "id", None),
        # ✅ NUEVO: estado de revocación permanente
        is_revoked=False,
    )

    db.add(rec)
    db.commit()
    db.refresh(rec)

    return ApiKeyCreateOut(
        id=rec.id,
        name=rec.name,
        server=rec.server,
        api_key=api_key_plain,
        is_active=rec.is_active,
        created_at=_dt(getattr(rec, "created_at", None)),
    )


@router.get("", response_model=dict)
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    server: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
):
    """
    Lista API keys (NO devuelve la llave).
    ✅ NO lista revocadas (is_revoked=True), por lo tanto "desaparecen del front".
    """
    _require_admin(current_user)

    q = db.query(ApiKey).filter(ApiKey.is_revoked.is_(False))

    if server and server != "all":
        q = q.filter(ApiKey.server == server)

    if is_active is not None:
        q = q.filter(ApiKey.is_active.is_(is_active))

    q = q.order_by(ApiKey.id.desc())

    total = q.count()
    rows: List[ApiKey] = q.offset(offset).limit(limit).all()

    items = [
        ApiKeyListItem(
            id=r.id,
            name=r.name,
            server=r.server,
            is_active=r.is_active,
            created_at=_dt(getattr(r, "created_at", None)),
            last_used_at=_dt(getattr(r, "last_used_at", None)),
            created_by_user_id=getattr(r, "created_by_user_id", None),
        ).model_dump()
        for r in rows
    ]

    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.patch("/{api_key_id}/disable", response_model=dict)
def disable_api_key(
    api_key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    rec = _get_api_key_or_404(db, api_key_id)

    # si ya fue revocada, no tiene sentido “disable”; es idempotente
    if getattr(rec, "is_revoked", False):
        return {"id": rec.id, "server": rec.server, "is_active": rec.is_active}

    rec.is_active = False
    db.commit()

    return {"id": rec.id, "server": rec.server, "is_active": rec.is_active}


@router.patch("/{api_key_id}/enable", response_model=dict)
def enable_api_key(
    api_key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    rec = _get_api_key_or_404(db, api_key_id)

    # ✅ Si está revocada, NO se puede reactivar.
    if getattr(rec, "is_revoked", False):
        raise HTTPException(status_code=400, detail="API Key revocada: no se puede reactivar.")

    rec.is_active = True
    db.commit()

    return {"id": rec.id, "server": rec.server, "is_active": rec.is_active}


@router.delete("/{api_key_id}", response_model=dict)
def delete_api_key(
    api_key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    rec = _get_api_key_or_404(db, api_key_id)
    db.delete(rec)
    db.commit()

    return {"deleted": True, "id": api_key_id}


@router.post("/{api_key_id}/revoke", response_model=dict)
def revoke_api_key(
    api_key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoca una API key (definitivo):
    - is_revoked=True
    - is_active=False
    - invalida el hash (aunque alguien tenga la key vieja)
    - ✅ luego ya NO se lista y NO se puede reactivar
    """
    _require_admin(current_user)

    rec = _get_api_key_or_404(db, api_key_id)

    # idempotente
    if getattr(rec, "is_revoked", False):
        return {"revoked": True, "id": rec.id, "server": rec.server, "is_active": rec.is_active}

    rec.is_active = False
    rec.is_revoked = True

    junk_plain, _ = generate_api_key()
    rec.hashed_key = hash_api_key(junk_plain)

    db.commit()
    return {"revoked": True, "id": rec.id, "server": rec.server, "is_active": rec.is_active}
