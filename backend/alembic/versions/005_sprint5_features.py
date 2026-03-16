"""Add Sprint 5 tables: tags, bucket_tags, bookmarks, scan_schedules, audit_log.

Revision ID: 005
Revises: 004
Create Date: 2026-03-15

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Tags ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            color           TEXT DEFAULT '#6b7280',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, name)
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS bucket_tags (
            id              SERIAL PRIMARY KEY,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
            tag_id          INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(bucket_id, tag_id, user_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_bucket_tags_bucket ON bucket_tags(bucket_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_bucket_tags_tag ON bucket_tags(tag_id)")

    # ── Bookmarks ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS bookmarks (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            bucket_id       INTEGER REFERENCES buckets(id) ON DELETE CASCADE,
            file_id         INTEGER,
            note            TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id)")

    # ── Scan Schedules ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            keywords        TEXT NOT NULL DEFAULT '[]',
            companies       TEXT DEFAULT '[]',
            providers       TEXT DEFAULT '[]',
            frequency       TEXT NOT NULL DEFAULT 'daily' CHECK(frequency IN ('hourly','daily','weekly','monthly')),
            cron_expr       TEXT,
            is_active       BOOLEAN DEFAULT TRUE,
            last_run_at     TIMESTAMPTZ,
            next_run_at     TIMESTAMPTZ,
            last_job_id     INTEGER REFERENCES scan_jobs(id),
            config          TEXT DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_schedules_user ON scan_schedules(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_schedules_next ON scan_schedules(next_run_at)")

    # ── Audit Log ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action          TEXT NOT NULL,
            entity_type     TEXT,
            entity_id       INTEGER,
            details         TEXT,
            ip_address      TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log")
    op.execute("DROP TABLE IF EXISTS scan_schedules")
    op.execute("DROP TABLE IF EXISTS bookmarks")
    op.execute("DROP TABLE IF EXISTS bucket_tags")
    op.execute("DROP TABLE IF EXISTS tags")
