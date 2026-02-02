"""restore system_settings + dedupe entity_score_events alerts + unique index

Revision ID: 3e46369c15c4
Revises: b3471afb9284
Create Date: 2026-01-13

Objetivo:
1) Restaurar tabla system_settings (fue eliminada por una migración autogenerada previa).
2) Eliminar duplicados en entity_score_events para reason_type='alert' para permitir índice único.
3) Crear índice único parcial que impide duplicar el mismo alert por entidad.
"""

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3e46369c15c4"
down_revision: str = "b3471afb9284"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) Restaurar system_settings si no existe (idempotente)
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS system_settings (
            key VARCHAR(191) PRIMARY KEY,
            value VARCHAR NOT NULL DEFAULT '',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        """
    )

    # 2) Deduplicar entity_score_events para reason_type='alert'
    # Mantiene SOLO 1 fila por (entity_id, reason_type, reason_id) usando ctid (rápido/seguro).
    op.execute(
        """
        WITH dups AS (
          SELECT
            ctid,
            ROW_NUMBER() OVER (
              PARTITION BY entity_id, reason_type, reason_id
              ORDER BY ctid
            ) AS rn
          FROM entity_score_events
          WHERE reason_type = 'alert'
        )
        DELETE FROM entity_score_events e
        USING dups
        WHERE e.ctid = dups.ctid
          AND dups.rn > 1;
        """
    )

    # 3) Índice único parcial para evitar duplicados futuros del mismo alert por entidad
    op.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS uq_entity_score_event_alert_once
        ON entity_score_events (entity_id, reason_type, reason_id)
        WHERE reason_type = 'alert';
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS uq_entity_score_event_alert_once;")
    # No droppeamos system_settings en downgrade porque la app lo requiere para operar.

