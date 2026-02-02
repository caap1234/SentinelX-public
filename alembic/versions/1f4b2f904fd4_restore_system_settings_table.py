"""restore system_settings table

Revision ID: 1f4b2f904fd4
Revises: 3e46369c15c4
Create Date: 2026-01-13 10:17:45.609689

"""
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1f4b2f904fd4"
down_revision: str = "3e46369c15c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            key VARCHAR(191) PRIMARY KEY,
            value VARCHAR NOT NULL DEFAULT '',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )


def downgrade() -> None:
    # No la dropeamos por seguridad (la app la usa).
    pass

