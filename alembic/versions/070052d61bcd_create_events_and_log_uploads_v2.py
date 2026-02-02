"""create events and log_uploads v2

Revision ID: 070052d61bcd
Revises: d3efbfcb0aa0
Create Date: 2026-01-01 20:01:48.232499

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "070052d61bcd"
down_revision: Union[str, Sequence[str], None] = "d3efbfcb0aa0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_exists(name: str) -> bool:
    bind = op.get_bind()
    return bind.dialect.has_table(bind, name)


def _index_exists(table: str, index_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return any(ix.get("name") == index_name for ix in insp.get_indexes(table))


def upgrade() -> None:
    # ------------------------------------------------------------
    # 1) Crear log_uploads si aún no existe
    # ------------------------------------------------------------
    if not _table_exists("log_uploads"):
        op.create_table(
            "log_uploads",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("filename", sa.String(), nullable=False),
            sa.Column("server", sa.String(), nullable=False),
            sa.Column("tag", sa.String(), nullable=True),
            sa.Column("path", sa.String(), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(), nullable=False, server_default="uploaded"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("extra_meta", sa.JSON(), nullable=True, server_default=sa.text("'{}'::json")),
            sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column(
                "api_key_id",
                sa.Integer(),
                sa.ForeignKey("api_keys.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("uploader_type", sa.String(length=32), nullable=False, server_default="user"),
        )

        op.create_index("ix_log_uploads_id", "log_uploads", ["id"], unique=False)
        op.create_index("ix_log_uploads_server", "log_uploads", ["server"], unique=False)
        op.create_index("ix_log_uploads_status", "log_uploads", ["status"], unique=False)
        op.create_index("ix_log_uploads_uploaded_at", "log_uploads", ["uploaded_at"], unique=False)
        op.create_index("ix_log_uploads_server_uploaded_at", "log_uploads", ["server", "uploaded_at"], unique=False)

    # ------------------------------------------------------------
    # 2) Ajustes a events: quitar campos v1 y asegurar campos v2
    # ------------------------------------------------------------

    # (a) Quitar índices viejos (si existían) - v1: rule_id/severity
    # OJO: tu autogenerate usó op.f(...) pero el nombre real puede variar;
    # aquí removemos por nombre si existe.
    for idx in (
        op.f("ix_events_rule_id"),
        op.f("ix_events_rule_id_timestamp"),
        op.f("ix_events_severity"),
        op.f("ix_events_severity_timestamp"),
    ):
        if _index_exists("events", idx):
            op.drop_index(idx, table_name="events")

    # (b) Crear columnas que requiere tu modelo v2 si faltan:
    # - log_upload_id (FK a log_uploads.id ON DELETE SET NULL)
    # - extra como JSONB default {}
    #
    # Nota: Alembic no trae "if not exists" universal; usamos inspector.
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("events")}

    if "log_upload_id" not in cols:
        op.add_column("events", sa.Column("log_upload_id", sa.Integer(), nullable=True))
        op.create_foreign_key(
            "fk_events_log_upload_id_log_uploads",
            "events",
            "log_uploads",
            ["log_upload_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_index(op.f("ix_events_log_upload_id"), "events", ["log_upload_id"], unique=False)

    if "extra" in cols:
        # Asegurar que sea JSONB y tenga default {} (en Postgres)
        # Si ya es JSONB, el alter type no cambia nada; si era JSON, lo migra.
        op.alter_column(
            "events",
            "extra",
            existing_type=sa.JSON(),
            type_=postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        )
    else:
        op.add_column(
            "events",
            sa.Column(
                "extra",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )

    # (c) Quitar columnas v1 si aún existen
    # (autogenerate las quitó sin checar; aquí lo hacemos seguro)
    if "severity" in cols:
        op.drop_column("events", "severity")
    if "rule_id" in cols:
        op.drop_column("events", "rule_id")
    if "rule_name" in cols:
        op.drop_column("events", "rule_name")
    if "correlation_scope" in cols:
        op.drop_column("events", "correlation_scope")

    # (d) Asegurar índices v2 del modelo Event
    # simples
    if not _index_exists("events", op.f("ix_events_service")):
        op.create_index(op.f("ix_events_service"), "events", ["service"], unique=False)
    if not _index_exists("events", op.f("ix_events_source")):
        op.create_index(op.f("ix_events_source"), "events", ["source"], unique=False)

    # compuestos
    if not _index_exists("events", "ix_events_ip_client_timestamp"):
        op.create_index("ix_events_ip_client_timestamp", "events", ["ip_client", "timestamp_utc"], unique=False)
    if not _index_exists("events", "ix_events_service_timestamp"):
        op.create_index("ix_events_service_timestamp", "events", ["service", "timestamp_utc"], unique=False)
    if not _index_exists("events", "ix_events_source_timestamp"):
        op.create_index("ix_events_source_timestamp", "events", ["source", "timestamp_utc"], unique=False)

    # Estos 3 existen en tu modelo Event; si ya están, no duplica.
    if not _index_exists("events", "ix_events_server_timestamp"):
        op.create_index("ix_events_server_timestamp", "events", ["server", "timestamp_utc"], unique=False)
    if not _index_exists("events", "ix_events_source_timestamp"):
        # ya se creó arriba, pero por si lo quitaste, lo garantiza (no duplicará si ya existe)
        pass
    if not _index_exists("events", "ix_events_service_timestamp"):
        pass


def downgrade() -> None:
    # Downgrade conservador: revierte índices v2 añadidos y restaura columnas v1
    # (No eliminamos log_uploads por seguridad si ya había datos)
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = {c["name"] for c in insp.get_columns("events")}

    # quitar índices v2 añadidos
    for idx in (
        "ix_events_ip_client_timestamp",
        "ix_events_service_timestamp",
        "ix_events_source_timestamp",
        "ix_events_server_timestamp",
        op.f("ix_events_log_upload_id"),
        op.f("ix_events_service"),
        op.f("ix_events_source"),
    ):
        if _index_exists("events", idx):
            op.drop_index(idx, table_name="events")

    # quitar FK y columna log_upload_id si la agregamos
    if "log_upload_id" in cols:
        # drop fk si existe (por nombre)
        try:
            op.drop_constraint("fk_events_log_upload_id_log_uploads", "events", type_="foreignkey")
        except Exception:
            pass
        op.drop_column("events", "log_upload_id")

    # extra: lo dejamos como JSONB (no vale la pena bajar tipo), pero sí quitamos default si quieres
    if "extra" in cols:
        op.alter_column("events", "extra", server_default=None)

    # restaurar columnas v1 (si tu v1 las esperaba)
    if "severity" not in cols:
        op.add_column("events", sa.Column("severity", sa.VARCHAR(length=32), nullable=False, server_default="info"))
    if "rule_id" not in cols:
        op.add_column("events", sa.Column("rule_id", sa.VARCHAR(length=255), nullable=False, server_default="unknown"))
    if "rule_name" not in cols:
        op.add_column("events", sa.Column("rule_name", sa.TEXT(), nullable=False, server_default="unknown"))
    if "correlation_scope" not in cols:
        op.add_column(
            "events",
            sa.Column("correlation_scope", sa.VARCHAR(length=32), nullable=False, server_default="global"),
        )

    # recrear índices v1 (si los usabas)
    op.create_index(op.f("ix_events_rule_id"), "events", ["rule_id"], unique=False)
    op.create_index(op.f("ix_events_rule_id_timestamp"), "events", ["rule_id", "timestamp_utc"], unique=False)
    op.create_index(op.f("ix_events_severity"), "events", ["severity"], unique=False)
    op.create_index(op.f("ix_events_severity_timestamp"), "events", ["severity", "timestamp_utc"], unique=False)
