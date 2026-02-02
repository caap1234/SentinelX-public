from __future__ import annotations

import json
import os
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.models.incident_rule import IncidentRule


DEFAULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # app/
    "seed",
    "incident_rules_defaults.json",
)


def seed_default_incident_rules(db: Session) -> None:
    insp = inspect(db.get_bind())
    if not insp.has_table("incident_rules"):
        return

    # idempotente
    exists = db.query(IncidentRule.id).first()
    if exists:
        return

    if not os.path.exists(DEFAULTS_PATH):
        return

    with open(DEFAULTS_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)

    if not isinstance(items, list) or not items:
        return

    for r in items:
        if not isinstance(r, dict):
            continue
        if not r.get("code") or not r.get("name"):
            continue
        if not r.get("primary_entity_type") or not r.get("primary_entity_field"):
            continue

        db.add(IncidentRule(**r))

    db.commit()
