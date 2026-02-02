"""create rule_windows_events

Revision ID: 01fd65f0bed0
Revises: 1f4b2f904fd4
Create Date: 2026-01-13 19:52:48.039989

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "01fd65f0bed0"
down_revision = "1f4b2f904fd4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_window_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("rules_v2.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_key", sa.String(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("events.id", ondelete="CASCADE"), nullable=False),
        sa.Column("server", sa.String(), nullable=True),
        sa.Column("path", sa.String(), nullable=True),
        sa.Column("ip_client", sa.String(), nullable=True),
        sa.Column("ip_subnet24", sa.String(), nullable=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=True),
    )

    op.create_index("ix_rule_window_events_rule_id", "rule_window_events", ["rule_id"])
    op.create_index("ix_rule_window_events_group_key", "rule_window_events", ["group_key"])
    op.create_index("ix_rule_window_events_ts", "rule_window_events", ["ts"])
    op.create_index("ix_rule_window_events_event_id", "rule_window_events", ["event_id"])
    op.create_index("ix_rwe_rule_group_ts", "rule_window_events", ["rule_id", "group_key", "ts"])


def downgrade() -> None:
    op.drop_index("ix_rwe_rule_group_ts", table_name="rule_window_events")
    op.drop_index("ix_rule_window_events_event_id", table_name="rule_window_events")
    op.drop_index("ix_rule_window_events_ts", table_name="rule_window_events")
    op.drop_index("ix_rule_window_events_group_key", table_name="rule_window_events")
    op.drop_index("ix_rule_window_events_rule_id", table_name="rule_window_events")
    op.drop_table("rule_window_events")

