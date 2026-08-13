"""Add bucket attribution and exposure provenance.

Revision ID: 009
Revises: 008
Create Date: 2026-08-13
"""
from alembic import op

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS attribution_source TEXT DEFAULT NULL")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS attribution_confidence REAL DEFAULT NULL")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS ownership_status TEXT NOT NULL DEFAULT 'unverified'")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS exposure_type TEXT NOT NULL DEFAULT 'unknown'")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS exposure_evidence TEXT DEFAULT NULL")
    op.execute("ALTER TABLE buckets ADD COLUMN IF NOT EXISTS last_evidence_at TIMESTAMPTZ DEFAULT NULL")
    op.execute("""
        UPDATE buckets
        SET attribution_source = 'legacy_unverified', attribution_confidence = 0.1
        WHERE company_name IS NOT NULL AND company_name != '' AND attribution_source IS NULL
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_ownership_status ON buckets(ownership_status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_exposure_type ON buckets(exposure_type)")
    op.execute("""
        DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'buckets_ownership_status_check') THEN
                ALTER TABLE buckets ADD CONSTRAINT buckets_ownership_status_check
                CHECK (ownership_status IN ('unverified','pending','verified','rejected'));
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'buckets_exposure_type_check') THEN
                ALTER TABLE buckets ADD CONSTRAINT buckets_exposure_type_check
                CHECK (exposure_type IN ('unknown','public_listing','public_website','access_denied','existence_only'));
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'buckets_attribution_confidence_check') THEN
                ALTER TABLE buckets ADD CONSTRAINT buckets_attribution_confidence_check
                CHECK (attribution_confidence IS NULL OR attribution_confidence BETWEEN 0 AND 1);
            END IF;
        END $$;
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE buckets DROP CONSTRAINT IF EXISTS buckets_attribution_confidence_check")
    op.execute("ALTER TABLE buckets DROP CONSTRAINT IF EXISTS buckets_exposure_type_check")
    op.execute("ALTER TABLE buckets DROP CONSTRAINT IF EXISTS buckets_ownership_status_check")
    op.execute("DROP INDEX IF EXISTS idx_buckets_exposure_type")
    op.execute("DROP INDEX IF EXISTS idx_buckets_ownership_status")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS last_evidence_at")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS exposure_evidence")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS exposure_type")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS ownership_status")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS attribution_confidence")
    op.execute("ALTER TABLE buckets DROP COLUMN IF EXISTS attribution_source")
