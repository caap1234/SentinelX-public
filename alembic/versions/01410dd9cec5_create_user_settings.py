"""create user_settings

Revision ID: 01410dd9cec5
Revises: 131c9ffd0ed1
Create Date: 2026-01-07 00:39:10.524213
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "01410dd9cec5"
down_revision = "131c9ffd0ed1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    # Ya existe => no hacemos nada
    if insp.has_table("user_settings"):
        return

    op.create_table(
        "user_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(length=191), nullable=False),
        sa.Column("value", sa.Text(), nullable=False, server_default=sa.text("''")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("user_id", "key", name="uq_user_settings_user_id_key"),
    )
    op.create_index("ix_user_settings_user_id", "user_settings", ["user_id"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table("user_settings"):
        return

    idx = {i["name"] for i in insp.get_indexes("user_settings")}
    if "ix_user_settings_user_id" in idx:
        op.drop_index("ix_user_settings_user_id", table_name="user_settings")
    op.drop_table("user_settings")
