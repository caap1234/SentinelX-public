"""user_settings + incident_rules

Revision ID: 131c9ffd0ed1
Revises: be00bea23495
Create Date: 2026-01-07 00:30:10.898143
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "131c9ffd0ed1"
down_revision: Union[str, Sequence[str], None] = "be00bea23495"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return bool(insp.has_table(name))


def _index_exists(table_name: str, index_name: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    idx = insp.get_indexes(table_name) if insp.has_table(table_name) else []
    return any(i.get("name") == index_name for i in idx)


def upgrade() -> None:
    # ---------------------------
    # user_settings (per-user KV)
    # ---------------------------
    if not _has_table("user_settings"):
        op.create_table(
            "user_settings",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("key", sa.String(length=191), nullable=False),
            sa.Column("value", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint("user_id", "key", name="uq_user_settings_user_id_key"),
        )

    if _has_table("user_settings") and not _index_exists("user_settings", "ix_user_settings_user_id"):
        op.create_index("ix_user_settings_user_id", "user_settings", ["user_id"])

    # ---------------------------
    # incident_rules
    # ---------------------------
    if not _has_table("incident_rules"):
        op.create_table(
            "incident_rules",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("code", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("scope", sa.String(length=16), nullable=False, server_default=sa.text("'local'")),
            sa.Column("severity_base", sa.Integer(), nullable=False, server_default=sa.text("10")),
            sa.Column("score_bonus", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("window_seconds", sa.Integer(), nullable=False, server_default=sa.text("1800")),
            sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default=sa.text("3600")),
            sa.Column("primary_entity_type", sa.String(length=32), nullable=False),
            sa.Column("primary_entity_field", sa.String(length=128), nullable=False),
            sa.Column(
                "match",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column(
                "group_by",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("condition", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column(
                "tags",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column(
                "meta",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
            sa.UniqueConstraint("code", name="uq_incident_rules_code"),
        )

    # ---------------------------
    # incident_rule_state
    # ---------------------------
    if not _has_table("incident_rule_state"):
        op.create_table(
            "incident_rule_state",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column(
                "rule_id",
                sa.Integer(),
                sa.ForeignKey("incident_rules.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("group_key", sa.Text(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_incident_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "extra",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        )

    if _has_table("incident_rule_state") and not _index_exists("incident_rule_state", "ix_incident_rule_state_rule_id"):
        op.create_index("ix_incident_rule_state_rule_id", "incident_rule_state", ["rule_id"])


def downgrade() -> None:
    # Downgrade “safe”
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if insp.has_table("incident_rule_state"):
        idx = {i["name"] for i in insp.get_indexes("incident_rule_state")}
        if "ix_incident_rule_state_rule_id" in idx:
            op.drop_index("ix_incident_rule_state_rule_id", table_name="incident_rule_state")
        op.drop_table("incident_rule_state")

    if insp.has_table("incident_rules"):
        op.drop_table("incident_rules")

    if insp.has_table("user_settings"):
        idx = {i["name"] for i in insp.get_indexes("user_settings")}
        if "ix_user_settings_user_id" in idx:
            op.drop_index("ix_user_settings_user_id", table_name="user_settings")
        op.drop_table("user_settings")
