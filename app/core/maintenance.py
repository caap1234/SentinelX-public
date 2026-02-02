# app/core/maintenance.py
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Tuple, Dict, Any, Optional


def _default_uploaded_logs_dir() -> Path:
    """
    Default para DEV local:
      <repo>/app/uploaded_logs

    (Este archivo vive en: <repo>/app/core/maintenance.py)
    parents[1] => <repo>/app
    """
    app_dir = Path(__file__).resolve().parents[1]
    return app_dir / "uploaded_logs"


def get_uploaded_logs_dir(ensure_exists: bool = True) -> Path:
    """
    Permite configurar por env var:

      UPLOADED_LOGS_DIR=/app/uploaded_logs     (docker)
      UPLOADED_LOGS_DIR=/Users/.../app/uploaded_logs (local)
    """
    env = os.getenv("UPLOADED_LOGS_DIR", "").strip()
    if env:
        p = Path(env).expanduser()
        # No forzamos resolve si no existe
        if ensure_exists:
            p.mkdir(parents=True, exist_ok=True)
        return p.resolve() if p.exists() else p

    p = _default_uploaded_logs_dir().resolve()
    if ensure_exists:
        p.mkdir(parents=True, exist_ok=True)
    return p


def _safety_check(base_dir: Path) -> None:
    """
    Evita borrados accidentales si alguien configura mal UPLOADED_LOGS_DIR.
    """
    try:
        rp = base_dir.resolve()
    except Exception:
        rp = base_dir

    # Prohibidos (ajusta si necesitas)
    forbidden = {
        Path("/"),
        Path("/app"),
        Path("/tmp"),
        Path("/var"),
        Path("/home"),
    }

    if rp in forbidden:
        raise ValueError(f"Ruta demasiado peligrosa para limpiar: {rp}")

    # Debe terminar EXACTO en 'uploaded_logs'
    if rp.name != "uploaded_logs":
        raise ValueError(f"Refuso limpiar porque la ruta no termina en 'uploaded_logs': {rp}")

    # Evita paths demasiado cortos tipo "/uploaded_logs" (opcional, recomendado)
    if str(rp) in {"/uploaded_logs"}:
        raise ValueError(f"Ruta sospechosa para limpiar: {rp}")


def clean_uploaded_logs(base_dir: Optional[Path] = None) -> Tuple[int, int, Dict[str, Any]]:
    """
    Borra TODO el contenido dentro de base_dir (archivos y subcarpetas),
    pero NO borra el directorio base_dir en sí.

    Regresa:
      (removed_files, removed_dirs, meta)
    """
    if base_dir is None:
        base_dir = get_uploaded_logs_dir(ensure_exists=True)

    meta: Dict[str, Any] = {
        "path": str(base_dir),
        "exists": base_dir.exists(),
        "is_dir": base_dir.is_dir(),
        "errors": [],
    }

    if not base_dir.exists() or not base_dir.is_dir():
        return (0, 0, meta)

    try:
        _safety_check(base_dir)
    except Exception as e:
        meta["errors"].append(f"safety_check: {e}")
        return (0, 0, meta)

    removed_files = 0
    removed_dirs = 0

    for entry in base_dir.iterdir():
        try:
            # Symlinks: unlink sin seguir
            if entry.is_symlink():
                entry.unlink()
                removed_files += 1
                continue

            if entry.is_file():
                entry.unlink()
                removed_files += 1
                continue

            if entry.is_dir():
                shutil.rmtree(entry)
                removed_dirs += 1
                continue

            # Otros tipos raros
            entry.unlink()
            removed_files += 1

        except Exception as e:
            meta["errors"].append(f"{entry}: {e}")

    return (removed_files, removed_dirs, meta)
