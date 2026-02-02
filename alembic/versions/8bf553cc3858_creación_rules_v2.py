"""Creación rules v2

Revision ID: 8bf553cc3858
Revises: 4da052cf8c1c
Create Date: 2026-01-05 17:40:56.913902

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "8bf553cc3858"
down_revision = "4da052cf8c1c"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rules_v2",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),

        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),

        # Indexing key
        sa.Column("source", sa.String(64), nullable=False),       # ej. APACHE_ACCESS, EXIM_MAINLOG
        sa.Column("event_type", sa.String(64), nullable=False),   # ej. http_access, auth_login

        sa.Column("severity", sa.Integer(), nullable=False, server_default=sa.text("3")),

        # declarative core
        sa.Column("match", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("group_by", postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("window_seconds", sa.Integer(), nullable=False, server_default=sa.text("300")),
        sa.Column("let", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("condition", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default=sa.text("900")),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("emit", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),

        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ix_rules_v2_enabled", "rules_v2", ["enabled"])
    op.create_index("ix_rules_v2_source_event_type", "rules_v2", ["source", "event_type"])
    op.create_index("ix_rules_v2_source_event_type_enabled", "rules_v2", ["source", "event_type", "enabled"])

    op.create_table(
        "rule_states_v2",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("rules_v2.id", ondelete="CASCADE"), nullable=False),

        sa.Column("group_key", sa.Text(), nullable=False),

        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),

        sa.Column("extra", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ux_rule_states_v2_rule_group", "rule_states_v2", ["rule_id", "group_key"], unique=True)
    op.create_index("ix_rule_states_v2_rule_id", "rule_states_v2", ["rule_id"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),

        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("rules_v2.id", ondelete="SET NULL"), nullable=True),
        sa.Column("rule_name", sa.String(255), nullable=False),  # snapshot por si cambian/borra regla
        sa.Column("severity", sa.Integer(), nullable=False),

        sa.Column("server", sa.String(255), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("event_type", sa.String(64), nullable=True),

        sa.Column("group_key", sa.Text(), nullable=False),

        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),

        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),

        sa.Column("status", sa.String(32), nullable=False, server_default=sa.text("'open'")),
        sa.Column("disposition", sa.String(64), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(255), nullable=True),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    op.create_index("ix_alerts_triggered_at", "alerts", ["triggered_at"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_group_key", "alerts", ["group_key"])


def downgrade() -> None:
    op.drop_index("ix_alerts_group_key", table_name="alerts")
    op.drop_index("ix_alerts_rule_id", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_alerts_triggered_at", table_name="alerts")
    op.drop_table("alerts")

    op.drop_index("ix_rule_states_v2_rule_id", table_name="rule_states_v2")
    op.drop_index("ux_rule_states_v2_rule_group", table_name="rule_states_v2")
    op.drop_table("rule_states_v2")

    op.drop_index("ix_rules_v2_source_event_type_enabled", table_name="rules_v2")
    op.drop_index("ix_rules_v2_source_event_type", table_name="rules_v2")
    op.drop_index("ix_rules_v2_enabled", table_name="rules_v2")
    op.drop_table("rules_v2")
