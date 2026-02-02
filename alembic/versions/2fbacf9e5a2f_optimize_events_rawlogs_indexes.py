"""optimize events rawlogs indexes

Revision ID: 2fbacf9e5a2f
Revises: 31df08080b30
Create Date: 2026-01-30 13:43:01.630050
"""
from alembic import op

revision = "2fbacf9e5a2f"
down_revision = "31df08080b30"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NOTA:
    # rule_states_v2 ya tiene UNIQUE(rule_id, group_key) (de hecho hay 2).
    # No creamos otro, solo creamos los índices nuevos.

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_events_upload_pending_processing
        ON events (log_upload_id)
        WHERE engine_status IN ('pending','processing') AND log_upload_id IS NOT NULL
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_rawlogs_upload_id_id
        ON rawlogs (log_upload_id, id)
        WHERE log_upload_id IS NOT NULL
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_rawlogs_upload_id_id")
    op.execute("DROP INDEX IF EXISTS ix_events_upload_pending_processing")

