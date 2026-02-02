"""ensure uq_rule_states_v2_rule_group

Revision ID: 31df08080b30
Revises: 01fd65f0bed0
Create Date: 2026-01-26
"""
from alembic import op

revision = "31df08080b30"
down_revision = "01fd65f0bed0"
branch_labels = None
depends_on = None


def upgrade():
    # Idempotente:
    # - Si ya existe constraint con ese nombre -> no hacer nada
    # - Si ya existe index con ese nombre -> no hacer nada (evita DuplicateTable)
    # - Si ya existe *cualquier* unique index sobre (rule_id, group_key) -> no hacer nada
    # - Si no existe nada -> crea UNIQUE index (no constraint), suficiente para ON CONFLICT(rule_id, group_key)
    op.execute(
        """
        DO $$
        BEGIN
            -- 1) Si ya existe constraint con ese nombre, salir
            IF EXISTS (
                SELECT 1
                FROM pg_constraint
                WHERE conname = 'uq_rule_states_v2_rule_group'
            ) THEN
                RETURN;
            END IF;

            -- 2) Si ya existe un índice con ese nombre, salir
            IF EXISTS (
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind = 'i'
                  AND c.relname = 'uq_rule_states_v2_rule_group'
                  AND n.nspname = 'public'
            ) THEN
                RETURN;
            END IF;

            -- 3) Si ya existe cualquier UNIQUE index sobre (rule_id, group_key), salir
            IF EXISTS (
                SELECT 1
                FROM pg_index i
                JOIN pg_class t ON t.oid = i.indrelid
                JOIN pg_class idx ON idx.oid = i.indexrelid
                JOIN pg_attribute a1 ON a1.attrelid = t.oid AND a1.attnum = i.indkey[1]
                JOIN pg_attribute a2 ON a2.attrelid = t.oid AND a2.attnum = i.indkey[2]
                WHERE t.relname = 'rule_states_v2'
                  AND i.indisunique
                  AND i.indnatts = 2
                  AND a1.attname = 'rule_id'
                  AND a2.attname = 'group_key'
            ) THEN
                RETURN;
            END IF;

            -- 4) Crear UNIQUE index (no constraint)
            CREATE UNIQUE INDEX uq_rule_states_v2_rule_group
            ON public.rule_states_v2 (rule_id, group_key);
        END
        $$;
        """
    )


def downgrade():
    # Downgrade seguro: si existe como index, lo droppeamos.
    # (Si existiera como constraint, NO lo tocamos aquí para evitar romper estados manuales)
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind = 'i'
                  AND c.relname = 'uq_rule_states_v2_rule_group'
                  AND n.nspname = 'public'
            ) THEN
                DROP INDEX public.uq_rule_states_v2_rule_group;
            END IF;
        END
        $$;
        """
    )

