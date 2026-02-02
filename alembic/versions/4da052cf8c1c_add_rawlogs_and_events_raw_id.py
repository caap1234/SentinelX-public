"""add rawlogs and events.raw_id

Revision ID: 4da052cf8c1c
Revises: 070052d61bcd
Create Date: 2026-01-02 17:33:02.386268

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "4da052cf8c1c"
down_revision: Union[str, Sequence[str], None] = "070052d61bcd"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1) rawlogs table
    op.create_table(
        "rawlogs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("server", sa.String(length=255), nullable=False),
        sa.Column("source_hint", sa.String(length=64), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),

        # opcionales pero útiles
        sa.Column("log_upload_id", sa.Integer(), sa.ForeignKey("log_uploads.id", ondelete="SET NULL"), nullable=True),
        sa.Column("line_no", sa.Integer(), nullable=True),

        # extra opcional (si luego quieres meter flags/metadata)
        sa.Column("extra", postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    )

    op.create_index("ix_rawlogs_server_created_at", "rawlogs", ["server", "created_at"])
    op.create_index("ix_rawlogs_source_hint_created_at", "rawlogs", ["source_hint", "created_at"])
    op.create_index("ix_rawlogs_log_upload_id", "rawlogs", ["log_upload_id"])

    # 2) add events.raw_id
    op.add_column("events", sa.Column("raw_id", sa.BigInteger(), nullable=True))
    op.create_foreign_key(
        "fk_events_raw_id",
        "events",
        "rawlogs",
        ["raw_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_events_raw_id", "events", ["raw_id"])


def downgrade() -> None:
    op.drop_index("ix_events_raw_id", table_name="events")
    op.drop_constraint("fk_events_raw_id", "events", type_="foreignkey")
    op.drop_column("events", "raw_id")

    op.drop_index("ix_rawlogs_log_upload_id", table_name="rawlogs")
    op.drop_index("ix_rawlogs_source_hint_created_at", table_name="rawlogs")
    op.drop_index("ix_rawlogs_server_created_at", table_name="rawlogs")
    op.drop_table("rawlogs")
