"""service checkpoint correction

Revision ID: b3471afb9284
Revises: 3eddbbaa9c1f
Create Date: 2026-01-13 09:56:22.145091

NOTA:
Este revision NO debe tocar tablas/índices ajenos. El autogenerate original era
peligroso (dropear system_settings, alterar columnas, etc.).

Objetivo real:
- Asegurar que service_checkpoints.meta sea JSONB (si ya lo es, no cambia nada).
- Blindar entity_score_events para que un mismo alert no sume score repetidamente
  por ejecuciones repetidas del cron (índice único parcial).
"""

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3471afb9284"
down_revision: str = "3eddbbaa9c1f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Asegurar JSONB en service_checkpoints.meta (idempotente).
    # Si ya es jsonb, no hace nada.
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'service_checkpoints'
              AND column_name = 'meta'
          ) THEN
            IF (
              SELECT udt_name
              FROM information_schema.columns
              WHERE table_name = 'service_checkpoints'
                AND column_name = 'meta'
            ) <> 'jsonb' THEN
              ALTER TABLE service_checkpoints
                ALTER COLUMN meta TYPE jsonb
                USING meta::jsonb;
            END IF;
          END IF;
        END $$;
        """
    )

    # 2) Índice único parcial: evita duplicados del mismo alert por entidad.
    # Esto previene que el cron vuelva a sumar el mismo alert si el checkpoint no avanzara.
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_entity_score_event_alert_once
        ON entity_score_events (entity_id, reason_type, reason_id)
        WHERE reason_type = 'alert';
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_entity_score_event_alert_once;")

