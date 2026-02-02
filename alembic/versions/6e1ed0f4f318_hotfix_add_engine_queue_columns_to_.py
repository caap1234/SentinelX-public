"""hotfix add engine queue columns to events

Revision ID: 6e1ed0f4f318
Revises: acb5efd06fac
Create Date: 2026-01-11

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6e1ed0f4f318'
down_revision: Union[str, Sequence[str], None] = 'acb5efd06fac'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('events', sa.Column('engine_status', sa.String(length=32), nullable=True))
    op.add_column('events', sa.Column('engine_claimed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('events', sa.Column('engine_processed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('events', sa.Column('engine_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('events', sa.Column('engine_error', sa.Text(), nullable=True))

    op.create_index(
        'ix_events_engine_status_created_at',
        'events',
        ['engine_status', 'created_at'],
    )
    op.create_index(
        'ix_events_engine_claimed_at',
        'events',
        ['engine_claimed_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_events_engine_claimed_at', table_name='events')
    op.drop_index('ix_events_engine_status_created_at', table_name='events')

    op.drop_column('events', 'engine_error')
    op.drop_column('events', 'engine_attempts')
    op.drop_column('events', 'engine_processed_at')
    op.drop_column('events', 'engine_claimed_at')
    op.drop_column('events', 'engine_status')
