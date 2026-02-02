from __future__ import annotations

from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.user import User
from app.routers.auth import get_current_user
from app.core.security import get_password_hash

router = APIRouter(prefix="/admin/users", tags=["admin_users"])


def _require_admin(current_user: User):
    if not getattr(current_user, "is_admin", False):
        raise HTTPException(status_code=403, detail="No autorizado (solo admin).")


class UserRow(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    is_admin: bool


class UserCreateIn(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    password: str = Field(..., min_length=6)
    # importante: el rol final lo decide el admin vía is_admin aquí (solo admin usa este endpoint)
    is_admin: bool = False


class UserUpdateIn(BaseModel):
    full_name: Optional[str] = None
    is_admin: Optional[bool] = None
    is_active: Optional[bool] = None


class UserPasswordUpdateIn(BaseModel):
    password: str = Field(..., min_length=6)


@router.get("", response_model=dict)
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _require_admin(current_user)

    q = db.query(User).order_by(User.id.desc())
    total = q.count()
    rows: List[User] = q.offset(offset).limit(limit).all()

    items = [
        UserRow(
            id=u.id,
            email=u.email,
            full_name=getattr(u, "full_name", None),
            is_active=bool(getattr(u, "is_active", True)),
            is_admin=bool(getattr(u, "is_admin", False)),
        ).model_dump()
        for u in rows
    ]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.post("", response_model=UserRow, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Ya existe un usuario con ese correo.")

    u = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        is_active=True,
        is_admin=bool(payload.is_admin),
    )
    db.add(u)
    db.commit()
    db.refresh(u)

    return UserRow(
        id=u.id,
        email=u.email,
        full_name=getattr(u, "full_name", None),
        is_active=bool(getattr(u, "is_active", True)),
        is_admin=bool(getattr(u, "is_admin", False)),
    )


@router.patch("/{user_id}", response_model=UserRow)
def update_user(
    user_id: int,
    payload: UserUpdateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if payload.full_name is not None:
        u.full_name = payload.full_name

    if payload.is_active is not None:
        u.is_active = bool(payload.is_active)

    if payload.is_admin is not None:
        u.is_admin = bool(payload.is_admin)

    db.commit()
    db.refresh(u)

    return UserRow(
        id=u.id,
        email=u.email,
        full_name=getattr(u, "full_name", None),
        is_active=bool(getattr(u, "is_active", True)),
        is_admin=bool(getattr(u, "is_admin", False)),
    )


@router.post("/{user_id}/password", response_model=dict)
def admin_set_user_password(
    user_id: int,
    payload: UserPasswordUpdateIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Admin puede cambiar la contraseña de cualquier usuario.
    """
    _require_admin(current_user)

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    u.hashed_password = get_password_hash(payload.password)
    db.commit()

    return {"updated": True, "id": user_id}


@router.delete("/{user_id}", response_model=dict)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)

    if user_id == getattr(current_user, "id", None):
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propio usuario.")

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    db.delete(u)
    db.commit()
    return {"deleted": True, "id": user_id}
