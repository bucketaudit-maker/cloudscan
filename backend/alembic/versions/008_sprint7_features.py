"""Sprint 7: New tables for 20 features.

Revision ID: 008
Revises: 007
Create Date: 2026-04-01
"""
from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Feature 5: Sensitive data findings
    op.execute("""
        CREATE TABLE IF NOT EXISTS sensitive_findings (
            id              SERIAL PRIMARY KEY,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
            file_id         INTEGER,
            filepath        TEXT NOT NULL,
            category        TEXT NOT NULL,
            severity        TEXT NOT NULL DEFAULT 'medium',
            compliance_controls TEXT DEFAULT '[]',
            scanned_at      TIMESTAMP DEFAULT NOW(),
            UNIQUE(bucket_id, filepath)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_sf_bucket ON sensitive_findings(bucket_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sf_severity ON sensitive_findings(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sf_category ON sensitive_findings(category)")

    # Feature 14: Ticket references
    op.execute("""
        CREATE TABLE IF NOT EXISTS ticket_refs (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            platform        TEXT NOT NULL DEFAULT 'jira',
            external_id     TEXT,
            title           TEXT NOT NULL,
            description     TEXT,
            priority        TEXT DEFAULT 'medium',
            status          TEXT DEFAULT 'created',
            bucket_id       INTEGER REFERENCES buckets(id),
            alert_id        INTEGER REFERENCES alerts(id),
            created_at      TIMESTAMP DEFAULT NOW(),
            updated_at      TIMESTAMP DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_tickets_user ON ticket_refs(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_tickets_bucket ON ticket_refs(bucket_id)")

    # Extend integrations type check to include teams and discord
    op.execute("""
        ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_type_check
    """)
    op.execute("""
        ALTER TABLE integrations ADD CONSTRAINT integrations_type_check
        CHECK (type IN ('slack','jira','teams','discord','linear','siem'))
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS ticket_refs")
    op.execute("DROP TABLE IF EXISTS sensitive_findings")
    op.execute("ALTER TABLE integrations DROP CONSTRAINT IF EXISTS integrations_type_check")
    op.execute("ALTER TABLE integrations ADD CONSTRAINT integrations_type_check CHECK (type IN ('slack','jira'))")
