from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.models.user import User
from app.core.security import hash_password


def seed_admin_user(
    db: Session,
    email: str,
    password: str,
    full_name: str = "Admin",
) -> None:
    # Si la tabla users no existe todavía, NO truena el startup.
    insp = inspect(db.get_bind())
    if not insp.has_table("users"):
        return

    exists = db.query(User).filter(User.email == email).first()
    if exists:
        return

    u = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        is_active=True,
        is_admin=True,
    )
    db.add(u)
    db.commit()
