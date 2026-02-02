from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object
config = context.config

# Logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# IMPORTANT: importa Base y modelos para que target_metadata tenga todo
from app.db import Base  # noqa: E402

# Si tienes un app/models/__init__.py que importa todos, con esto basta:
# from app import models  # noqa: F401,E402
#
# Si no, importa explícitamente tus modelos principales aquí:
from app.models.user import User  # noqa: F401,E402
from app.models.api_key import ApiKey  # noqa: F401,E402
from app.models.log_upload import LogUpload  # noqa: F401,E402
from app.models.job_state import JobState  # noqa: F401,E402
from app.models.event import Event
from app.models.raw_log import RawLog
from app.models.alert import Alert
from app.models.rule_state_v2 import RuleStateV2
from app.models.rule_v2 import RuleV2
from app.models.entity_score_event import EntityScoreEvent
from app.models.entity import Entity
from app.models.incident_alert import IncidentAlert
from app.models.incident_entity import  IncidentEntity
from app.models.incident_rule_state import IncidentRuleState
from app.models.incident_rule import IncidentRule
from app.models.incident import Incident
from app.models.service_checkpoint import ServiceCheckpoint
from app.models.user_setting import UserSetting

target_metadata = Base.metadata


def _get_db_url() -> str:
    # 1) docker-compose env var
    url = os.getenv("DATABASE_URL")
    if url:
        return url

    # 2) fallback: alembic.ini (si lo tienes configurado ahí)
    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url:
        return ini_url

    raise RuntimeError("DATABASE_URL no está configurada y alembic.ini no trae sqlalchemy.url")


def run_migrations_offline() -> None:
    url = _get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _get_db_url()

    # Fuerza que engine_from_config use ESTE URL (no el del ini si estuviera distinto)
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        future=True,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
