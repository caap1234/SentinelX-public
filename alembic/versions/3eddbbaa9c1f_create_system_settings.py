"""create system_settings

Revision ID: 3eddbbaa9c1f
Revises: 6e1ed0f4f318
Create Date: 2026-01-12 00:37:55.831889

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "3eddbbaa9c1f"
down_revision: Union[str, Sequence[str], None] = "6e1ed0f4f318"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(length=191), primary_key=True, nullable=False),
        sa.Column("value", sa.String(), nullable=False, server_default=""),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    op.drop_table("system_settings")
