"""Add saved_searches and webhook_configs tables for Sprint 1 & 2 features.

Revision ID: 003
Revises: 002
Create Date: 2026-03-14

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Saved searches (Sprint 2)
    op.execute("""
        CREATE TABLE IF NOT EXISTS saved_searches (
            id           SERIAL PRIMARY KEY,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name         TEXT NOT NULL,
            query_params TEXT NOT NULL,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_saved_searches_user ON saved_searches(user_id)")

    # Webhook configs (Sprint 1)
    op.execute("""
        CREATE TABLE IF NOT EXISTS webhook_configs (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            url             TEXT NOT NULL,
            secret          TEXT,
            event_types     TEXT NOT NULL DEFAULT '["critical","high"]',
            is_active       BOOLEAN NOT NULL DEFAULT TRUE,
            last_triggered  TIMESTAMPTZ,
            failure_count   INTEGER NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_webhook_configs_user ON webhook_configs(user_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_webhook_configs_user")
    op.execute("DROP TABLE IF EXISTS webhook_configs")
    op.execute("DROP INDEX IF EXISTS idx_saved_searches_user")
    op.execute("DROP TABLE IF EXISTS saved_searches")
