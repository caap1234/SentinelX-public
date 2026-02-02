# app/core/bootstrap_rules_v2.py
from __future__ import annotations

import json
import os
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.models.rule_v2 import RuleV2


DEFAULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # app/
    "seed",
    "rules_v2_defaults.json",
)


def seed_default_rules_v2(db: Session) -> None:
    insp = inspect(db.get_bind())
    if not insp.has_table("rules_v2"):
        return

    # Si ya hay reglas, no tocar (idempotente)
    exists = db.query(RuleV2.id).first()
    if exists:
        return

    if not os.path.exists(DEFAULTS_PATH):
        return

    with open(DEFAULTS_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)

    if not isinstance(items, list) or not items:
        return

    for r in items:
        # Seguridad mínima: evita insert de basura
        if not isinstance(r, dict):
            continue
        if not r.get("name") or not r.get("source") or not r.get("event_type"):
            continue

        db.add(RuleV2(**r))

    db.commit()
