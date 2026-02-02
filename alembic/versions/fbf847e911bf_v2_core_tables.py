"""v2 core tables (fix FK ondelete, JSONB, keep uq_users_email)

Revision ID: fbf847e911bf
Revises: 7238f5cd5ab5
Create Date: 2026-01-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "fbf847e911bf"
down_revision: Union[str, Sequence[str], None] = "7238f5cd5ab5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""

    # 1) FK api_keys.created_by_user_id -> users.id
    #    Mantener ON DELETE SET NULL y nombre estable.
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.api_keys') IS NOT NULL AND to_regclass('public.users') IS NOT NULL THEN
                ALTER TABLE public.api_keys
                    DROP CONSTRAINT IF EXISTS api_keys_created_by_user_id_fkey;

                ALTER TABLE public.api_keys
                    ADD CONSTRAINT api_keys_created_by_user_id_fkey
                    FOREIGN KEY (created_by_user_id)
                    REFERENCES public.users(id)
                    ON DELETE SET NULL;
            END IF;
        END $$;
        """
    )

    # 2) log_uploads.extra_meta: JSON -> JSONB (con USING para datos existentes)
    op.alter_column(
        "log_uploads",
        "extra_meta",
        existing_type=postgresql.JSON(astext_type=sa.Text()),
        type_=postgresql.JSONB(astext_type=sa.Text()),
        existing_nullable=True,
        postgresql_using="extra_meta::jsonb",
    )

    # 3) NO dropear uq_users_email.
    #    Ese índice asegura unicidad de users.email (lo dejaremos tal cual).
    #    (Si luego quieres renombrarlo o migrar a constraint, lo hacemos en otra revisión.)


def downgrade() -> None:
    """Downgrade schema."""

    # Revertir JSONB -> JSON (si realmente quieres rollback)
    op.alter_column(
        "log_uploads",
        "extra_meta",
        existing_type=postgresql.JSONB(astext_type=sa.Text()),
        type_=postgresql.JSON(astext_type=sa.Text()),
        existing_nullable=True,
        postgresql_using="extra_meta::json",
    )

    # Revertir FK a estado previo (sin ON DELETE o con el que prefieras)
    # Aquí lo dejamos sin ON DELETE, como el autogenerate original,
    # pero si quieres, también puede quedarse con SET NULL.
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.api_keys') IS NOT NULL AND to_regclass('public.users') IS NOT NULL THEN
                ALTER TABLE public.api_keys
                    DROP CONSTRAINT IF EXISTS api_keys_created_by_user_id_fkey;

                ALTER TABLE public.api_keys
                    ADD CONSTRAINT api_keys_created_by_user_id_fkey
                    FOREIGN KEY (created_by_user_id)
                    REFERENCES public.users(id);
            END IF;
        END $$;
        """
    )

    # uq_users_email lo dejamos intacto también en downgrade (no tocamos unicidad).
