"""Add Sprint 6 tables: 2FA, scan snapshots, alert rules, CSRF tokens, dashboard stats.

Revision ID: 006
Revises: 005
Create Date: 2026-03-22

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Two-Factor Authentication ──
    op.execute("""
        ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT NULL
    """)
    op.execute("""
        ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE
    """)
    op.execute("""
        ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_backup_codes TEXT DEFAULT NULL
    """)

    # ── Scan Snapshots (for drift detection) ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_snapshots (
            id              SERIAL PRIMARY KEY,
            scan_job_id     INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
            status          TEXT NOT NULL,
            file_count      INTEGER DEFAULT 0,
            total_size_bytes BIGINT DEFAULT 0,
            file_hashes     TEXT DEFAULT '[]',
            captured_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(scan_job_id, bucket_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_snapshots_job ON scan_snapshots(scan_job_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_snapshots_bucket ON scan_snapshots(bucket_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_snapshots_time ON scan_snapshots(captured_at)")

    # ── Scan Diffs (computed differences between snapshots) ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_diffs (
            id              SERIAL PRIMARY KEY,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
            old_snapshot_id INTEGER REFERENCES scan_snapshots(id) ON DELETE SET NULL,
            new_snapshot_id INTEGER NOT NULL REFERENCES scan_snapshots(id) ON DELETE CASCADE,
            diff_type       TEXT NOT NULL CHECK(diff_type IN ('new_bucket','status_change','files_added','files_removed','size_change')),
            summary         TEXT NOT NULL,
            details         TEXT DEFAULT '{}',
            severity        TEXT DEFAULT 'info' CHECK(severity IN ('critical','high','medium','low','info')),
            is_reviewed     BOOLEAN DEFAULT FALSE,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_diffs_bucket ON scan_diffs(bucket_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_diffs_new_snap ON scan_diffs(new_snapshot_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_diffs_created ON scan_diffs(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_diffs_severity ON scan_diffs(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_diffs_unreviewed ON scan_diffs(is_reviewed)")

    # ── Custom Alert Rules ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS alert_rules (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name            TEXT NOT NULL,
            description     TEXT,
            is_active       BOOLEAN DEFAULT TRUE,
            conditions      TEXT NOT NULL DEFAULT '[]',
            actions         TEXT NOT NULL DEFAULT '["alert"]',
            severity        TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
            match_count     INTEGER DEFAULT 0,
            last_matched_at TIMESTAMPTZ,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alert_rules_active ON alert_rules(is_active)")

    # ── CSRF Tokens ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS csrf_tokens (
            id              SERIAL PRIMARY KEY,
            token           TEXT UNIQUE NOT NULL,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            session_id      TEXT,
            expires_at      TIMESTAMPTZ NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_csrf_tokens_token ON csrf_tokens(token)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_csrf_tokens_expires ON csrf_tokens(expires_at)")

    # ── Dashboard Stats Cache ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS dashboard_stats_cache (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            stat_type       TEXT NOT NULL,
            data            TEXT NOT NULL DEFAULT '{}',
            computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, stat_type)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_cache_user ON dashboard_stats_cache(user_id)")

    # ── Additional performance indexes ──
    op.execute("CREATE INDEX IF NOT EXISTS idx_files_bucket_ext ON files(bucket_id, extension)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_files_content_type ON files(content_type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_files_last_modified ON files(last_modified)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_first_seen ON buckets(first_seen)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_buckets_status_provider ON buckets(status, provider_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(is_resolved)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_due ON remediations(due_date)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_completed ON remediations(completed_at)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_by ON scan_jobs(created_by)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_scan_jobs_completed ON scan_jobs(completed_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS dashboard_stats_cache")
    op.execute("DROP TABLE IF EXISTS csrf_tokens")
    op.execute("DROP TABLE IF EXISTS alert_rules")
    op.execute("DROP TABLE IF EXISTS scan_diffs")
    op.execute("DROP TABLE IF EXISTS scan_snapshots")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS totp_secret")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS totp_enabled")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS totp_backup_codes")
