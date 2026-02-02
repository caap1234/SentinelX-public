"""add engine queue fields to events

Revision ID: acb5efd06fac
Revises: 01410dd9cec5
Create Date: 2026-01-11 11:52:08.815883

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'acb5efd06fac'
down_revision: Union[str, Sequence[str], None] = '01410dd9cec5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
