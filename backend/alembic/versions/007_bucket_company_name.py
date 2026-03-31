"""Add company_name column to buckets table.

Revision ID: 007
Revises: 006
Create Date: 2026-03-30

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE buckets ADD COLUMN IF NOT EXISTS company_name TEXT DEFAULT NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_company ON buckets(company_name)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_buckets_company")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS company_name")
