"""v2 initial schema

Revision ID: 753c4d87b9cc
Revises: affb72fd98a8
Create Date: 2026-01-01 15:30:35.638924

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "753c4d87b9cc"
down_revision: Union[str, Sequence[str], None] = "affb72fd98a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # --- add new table ---
    op.create_table(
        "job_state",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_name", sa.String(length=128), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_job_state_job_name"), "job_state", ["job_name"], unique=True)

    # --- drop legacy v1 tables (safe for fresh DBs) ---
    # Si existen, las borramos en orden seguro. Si no existen, no pasa nada.
    # CASCADE por si hubiera FKs colgando.
    op.execute("DROP TABLE IF EXISTS public.incident_events CASCADE;")
    op.execute("DROP TABLE IF EXISTS public.incidents CASCADE;")
    op.execute("DROP TABLE IF EXISTS public.ip_profiles CASCADE;")
    op.execute("DROP TABLE IF EXISTS public.siem_events CASCADE;")

    # --- adjust FK on log_uploads ONLY if the table exists ---
    # En DB fresh (Docker) log_uploads aún no existe en este punto -> NO debemos tocarla.
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.log_uploads') IS NOT NULL THEN
                ALTER TABLE public.log_uploads
                    DROP CONSTRAINT IF EXISTS log_uploads_api_key_id_fkey;

                IF to_regclass('public.api_keys') IS NOT NULL THEN
                    ALTER TABLE public.log_uploads
                        ADD CONSTRAINT log_uploads_api_key_id_fkey
                        FOREIGN KEY (api_key_id)
                        REFERENCES public.api_keys (id)
                        ON DELETE SET NULL;
                END IF;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    """Downgrade schema."""

    # job_state
    op.drop_index(op.f("ix_job_state_job_name"), table_name="job_state")
    op.drop_table("job_state")

    # (Opcional) no recreamos tablas legacy v1 en downgrade.
    # Si algún día necesitas rollback real con v1, se arma una migración específica.
