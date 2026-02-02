# app/core/security.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple
import secrets
import hmac
import hashlib

from jose import jwt, JWTError
from passlib.context import CryptContext

from app.config import settings

# ------------------------------
# Passwords (usuarios)
# ------------------------------
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto",
)

ALGORITHM = "HS256"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# ✅ Alias para compatibilidad con seed_admin_user / otros módulos
def hash_password(password: str) -> str:
    return get_password_hash(password)


# ------------------------------
# JWT
# ------------------------------
def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    to_encode = data.copy()
    if expires_delta is not None:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# -------------------------------------------------------------------
# API KEYS (para ingesta desde servidores)
#
# Formato:
#   sx_live_<public_id>.<secret>
#
# En BD (ApiKey.hashed_key) guardamos SOLO:
#   secret_hash (HMAC hex)
# -------------------------------------------------------------------

API_KEY_PREFIX = "sx_live"


def generate_api_key(prefix: str = API_KEY_PREFIX) -> Tuple[str, str]:
    """
    Genera:
      - api_key_plain: sx_live_<public_id>.<secret>   (se muestra una sola vez)
      - public_id:     <public_id>                   (opcional, solo informativo)
    """
    public_id = secrets.token_urlsafe(12).replace("-", "").replace("_", "")
    secret = secrets.token_urlsafe(32)

    api_key_plain = f"{prefix}_{public_id}.{secret}"
    return api_key_plain, public_id


def _api_key_hmac(secret: str) -> str:
    """
    HMAC-SHA256(secret) usando settings.SECRET_KEY como key.
    Devuelve hex string.
    """
    key = settings.SECRET_KEY.encode("utf-8")
    msg = secret.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def parse_api_key(api_key_plain: str) -> Tuple[str, str]:
    """
    Parsea sx_live_<public_id>.<secret> -> (public_id, secret)
    """
    api_key_plain = (api_key_plain or "").strip()

    if "." not in api_key_plain:
        raise ValueError("Formato inválido de API key (falta '.')")

    left, secret = api_key_plain.split(".", 1)

    if not left.startswith(f"{API_KEY_PREFIX}_"):
        raise ValueError("Prefijo inválido de API key")

    public_id = left.replace(f"{API_KEY_PREFIX}_", "", 1).strip()

    if not public_id or not secret:
        raise ValueError("API key inválida (id/secret vacío)")

    return public_id, secret


def hash_api_key(api_key_plain: str) -> str:
    """
    Recibe sx_live_<public_id>.<secret> y devuelve:
      - secret_hash (HMAC hex)  -> se guarda en ApiKey.hashed_key
    """
    _public_id, secret = parse_api_key(api_key_plain)
    return _api_key_hmac(secret)


def verify_api_key(api_key_plain: str, stored_secret_hash: str) -> bool:
    """
    Verifica una API key contra el hashed_key guardado en BD.
    """
    try:
        _public_id, secret = parse_api_key(api_key_plain)
        calc = _api_key_hmac(secret)
        return hmac.compare_digest(calc, stored_secret_hash)
    except Exception:
        return False
