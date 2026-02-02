"""v2 core tables

Revision ID: 7238f5cd5ab5
Revises: 753c4d87b9cc
Create Date: 2026-01-01 17:15:36.601624

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7238f5cd5ab5"
down_revision: Union[str, Sequence[str], None] = "753c4d87b9cc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- USERS ---
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS public.users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            full_name VARCHAR(255),
            hashed_password VARCHAR(255) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON public.users(email);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_id ON public.users(id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON public.users(email);")

    # --- API_KEYS ---
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS public.api_keys (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            server VARCHAR(255) NOT NULL,
            hashed_key VARCHAR(255) NOT NULL,

            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
            revoked_at TIMESTAMPTZ NULL,

            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_used_at TIMESTAMPTZ NULL,

            created_by_user_id INTEGER NULL
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_api_keys_id ON public.api_keys(id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_api_keys_server ON public.api_keys(server);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_api_keys_is_revoked ON public.api_keys(is_revoked);")

    # FK api_keys.created_by_user_id -> users.id  (SET NULL)
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.users') IS NOT NULL AND to_regclass('public.api_keys') IS NOT NULL THEN
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

    # --- LOG_UPLOADS ---
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS public.log_uploads (
            id SERIAL PRIMARY KEY,

            filename VARCHAR(255) NOT NULL,
            server VARCHAR(255) NOT NULL,
            tag VARCHAR(255),

            path VARCHAR(255) NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,

            status VARCHAR(255) NOT NULL DEFAULT 'uploaded',
            error_message TEXT,

            extra_meta JSONB DEFAULT '{}'::jsonb,

            uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),

            user_id INTEGER NULL,
            api_key_id INTEGER NULL,

            uploader_type VARCHAR(32) NOT NULL DEFAULT 'user'
        );
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS ix_log_uploads_id ON public.log_uploads(id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_log_uploads_server ON public.log_uploads(server);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_log_uploads_status ON public.log_uploads(status);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_log_uploads_uploaded_at ON public.log_uploads(uploaded_at);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_log_uploads_server_uploaded_at ON public.log_uploads(server, uploaded_at);")

    # FKs log_uploads.user_id/api_key_id -> users/api_keys  (SET NULL)
    op.execute(
        """
        DO $$
        BEGIN
            IF to_regclass('public.users') IS NOT NULL AND to_regclass('public.log_uploads') IS NOT NULL THEN
                ALTER TABLE public.log_uploads
                    DROP CONSTRAINT IF EXISTS log_uploads_user_id_fkey;

                ALTER TABLE public.log_uploads
                    ADD CONSTRAINT log_uploads_user_id_fkey
                    FOREIGN KEY (user_id)
                    REFERENCES public.users(id)
                    ON DELETE SET NULL;
            END IF;

            IF to_regclass('public.api_keys') IS NOT NULL AND to_regclass('public.log_uploads') IS NOT NULL THEN
                ALTER TABLE public.log_uploads
                    DROP CONSTRAINT IF EXISTS log_uploads_api_key_id_fkey;

                ALTER TABLE public.log_uploads
                    ADD CONSTRAINT log_uploads_api_key_id_fkey
                    FOREIGN KEY (api_key_id)
                    REFERENCES public.api_keys(id)
                    ON DELETE SET NULL;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE IF EXISTS public.log_uploads DROP CONSTRAINT IF EXISTS log_uploads_api_key_id_fkey;")
    op.execute("ALTER TABLE IF EXISTS public.log_uploads DROP CONSTRAINT IF EXISTS log_uploads_user_id_fkey;")
    op.execute("ALTER TABLE IF EXISTS public.api_keys DROP CONSTRAINT IF EXISTS api_keys_created_by_user_id_fkey;")

    op.execute("DROP TABLE IF EXISTS public.log_uploads;")
    op.execute("DROP TABLE IF EXISTS public.api_keys;")
    op.execute("DROP TABLE IF EXISTS public.users;")