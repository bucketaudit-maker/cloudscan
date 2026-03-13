"""Add AI feature columns: file classification, bucket risk scoring, alert priority.

Revision ID: 002
Revises: 001
Create Date: 2025-06-01

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # AI classification on files
    op.execute("ALTER TABLE files ADD COLUMN IF NOT EXISTS ai_classification TEXT DEFAULT NULL")
    op.execute("ALTER TABLE files ADD COLUMN IF NOT EXISTS ai_confidence REAL DEFAULT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_files_ai_classification ON files(ai_classification)")

    # Risk scoring on buckets
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT NULL")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS risk_level TEXT DEFAULT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_risk_score ON buckets(risk_score)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_risk_level ON buckets(risk_level)")

    # AI priority scoring on alerts
    op.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_priority_score INTEGER DEFAULT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ai_priority ON alerts(ai_priority_score)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_alerts_ai_priority")
    op.execute("ALTER TABLE alerts DROP COLUMN IF EXISTS ai_priority_score")

    op.execute("DROP INDEX IF EXISTS idx_buckets_risk_level")
    op.execute("DROP INDEX IF EXISTS idx_buckets_risk_score")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS risk_level")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS risk_score")

    op.execute("DROP INDEX IF EXISTS idx_files_ai_classification")
    op.execute("ALTER TABLE files DROP COLUMN IF EXISTS ai_confidence")
    op.execute("ALTER TABLE files DROP COLUMN IF EXISTS ai_classification")
