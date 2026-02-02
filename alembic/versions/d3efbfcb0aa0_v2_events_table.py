"""v2 events table

Revision ID: d3efbfcb0aa0
Revises: fbf847e911bf
Create Date: 2026-01-01 17:40:07.359880

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "d3efbfcb0aa0"
down_revision: Union[str, Sequence[str], None] = "fbf847e911bf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # --- Events table (v2) ---
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("server", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("service", sa.String(length=255), nullable=False),
        sa.Column("ip_client", postgresql.INET(), nullable=True),
        sa.Column("ip_server", postgresql.INET(), nullable=True),
        sa.Column("domain", sa.Text(), nullable=True),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_name", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column(
            "correlation_scope",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'local'"),
        ),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column(
            "extra",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("log_upload_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["log_upload_id"],
            ["log_uploads.id"],
            ondelete="SET NULL",
            name="events_log_upload_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="events_pkey"),
    )

    # Indexes (alineados al modelo Event)
    op.create_index(op.f("ix_events_timestamp_utc"), "events", ["timestamp_utc"], unique=False)
    op.create_index(op.f("ix_events_server"), "events", ["server"], unique=False)
    op.create_index(op.f("ix_events_rule_id"), "events", ["rule_id"], unique=False)
    op.create_index(op.f("ix_events_severity"), "events", ["severity"], unique=False)
    op.create_index(op.f("ix_events_ip_client"), "events", ["ip_client"], unique=False)
    op.create_index(op.f("ix_events_log_upload_id"), "events", ["log_upload_id"], unique=False)

    op.create_index("ix_events_server_timestamp", "events", ["server", "timestamp_utc"], unique=False)
    op.create_index("ix_events_rule_id_timestamp", "events", ["rule_id", "timestamp_utc"], unique=False)
    op.create_index("ix_events_severity_timestamp", "events", ["severity", "timestamp_utc"], unique=False)

    # --- Legacy cleanup (safe / idempotent) ---
    # En DB nueva (Docker) no existe -> IF EXISTS evita crash.
    op.execute("DROP TABLE IF EXISTS public.system_settings CASCADE;")


def downgrade() -> None:
    """Downgrade schema."""

    # Recreate legacy table only if you really need to rollback (safe)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS public.system_settings (
            key VARCHAR(191) PRIMARY KEY,
            value VARCHAR NOT NULL DEFAULT '',
            updated_at TIMESTAMPTZ NOT NULL
        );
        """
    )

    op.drop_index("ix_events_severity_timestamp", table_name="events")
    op.drop_index("ix_events_rule_id_timestamp", table_name="events")
    op.drop_index("ix_events_server_timestamp", table_name="events")

    op.drop_index(op.f("ix_events_log_upload_id"), table_name="events")
    op.drop_index(op.f("ix_events_ip_client"), table_name="events")
    op.drop_index(op.f("ix_events_severity"), table_name="events")
    op.drop_index(op.f("ix_events_rule_id"), table_name="events")
    op.drop_index(op.f("ix_events_server"), table_name="events")
    op.drop_index(op.f("ix_events_timestamp_utc"), table_name="events")

    op.drop_table("events")
