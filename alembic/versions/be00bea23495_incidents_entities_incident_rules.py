"""incidents entities incident rules

Revision ID: be00bea23495
Revises: 8bf553cc3858
Create Date: 2026-01-06 20:56:51.941378

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "be00bea23495"
down_revision: Union[str, Sequence[str], None] = "8bf553cc3858"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incident_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="local"),
        sa.Column("severity_base", sa.Integer(), nullable=False, server_default="10"),
        sa.Column("score_bonus", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_seconds", sa.Integer(), nullable=False, server_default="1800"),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("primary_entity_type", sa.String(length=32), nullable=False),
        sa.Column("primary_entity_field", sa.String(length=128), nullable=False),
        sa.Column("match", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("group_by", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("condition", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("code", name="uq_incident_rules_code"),
    )

    op.create_table(
        "incident_rule_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("incident_rules.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_key", sa.Text(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_incident_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("extra", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_inc_rule_state_rule_group", "incident_rule_state", ["rule_id", "group_key"], unique=True)

    op.create_table(
        "incidents",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("code", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("severity_base", sa.Integer(), nullable=False),
        sa.Column("severity_current", sa.Integer(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("server", sa.String(length=255), nullable=True),
        sa.Column("primary_entity_type", sa.String(length=32), nullable=False),
        sa.Column("primary_entity_key", sa.String(length=255), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_activity_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disposition", sa.String(length=64), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("resolved_by", sa.String(length=255), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_incidents_code_status", "incidents", ["code", "status"], unique=False)
    op.create_index("ix_incidents_primary", "incidents", ["primary_entity_type", "primary_entity_key"], unique=False)

    op.create_table(
        "incident_alerts",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.BigInteger(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_id", sa.BigInteger(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="supporting"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),
    )

    op.create_table(
        "entities",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column("entity_key", sa.String(length=255), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="local"),
        sa.Column("score_current", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="clean"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("score_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attrs", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("entity_type", "entity_key", name="uq_entity_type_key"),
    )
    op.create_index("ix_entities_severity_score", "entities", ["severity", "score_current"], unique=False)

    op.create_table(
        "entity_score_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("entity_id", sa.BigInteger(), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delta", sa.Integer(), nullable=False),
        sa.Column("reason_type", sa.String(length=16), nullable=False),
        sa.Column("reason_id", sa.String(length=64), nullable=True),
        sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_entity_score_events_entity_ts", "entity_score_events", ["entity_id", "ts"], unique=False)

    op.create_table(
        "incident_entities",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.BigInteger(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entity_id", sa.BigInteger(), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relation", sa.String(length=32), nullable=False, server_default="related"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("incident_id", "entity_id", name="uq_incident_entity"),
    )

    op.create_table(
        "service_checkpoints",
        sa.Column("name", sa.String(length=64), primary_key=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("meta", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
    )


def downgrade() -> None:
    op.drop_table("service_checkpoints")
    op.drop_table("incident_entities")
    op.drop_index("ix_entity_score_events_entity_ts", table_name="entity_score_events")
    op.drop_table("entity_score_events")
    op.drop_index("ix_entities_severity_score", table_name="entities")
    op.drop_table("entities")
    op.drop_table("incident_alerts")
    op.drop_index("ix_incidents_primary", table_name="incidents")
    op.drop_index("ix_incidents_code_status", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_inc_rule_state_rule_group", table_name="incident_rule_state")
    op.drop_table("incident_rule_state")
    op.drop_table("incident_rules")
