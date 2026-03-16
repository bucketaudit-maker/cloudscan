"""Add Sprint 4 tables: organizations, notifications, reports, integrations, compliance, remediations.

Revision ID: 004
Revises: 003
Create Date: 2026-03-15

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Organizations ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id              SERIAL PRIMARY KEY,
            name            TEXT NOT NULL,
            slug            TEXT UNIQUE NOT NULL,
            owner_id        INTEGER NOT NULL REFERENCES users(id),
            api_key         TEXT UNIQUE,
            settings        TEXT DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS org_members (
            id              SERIAL PRIMARY KEY,
            org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role            TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','admin','member','viewer')),
            invited_by      INTEGER REFERENCES users(id),
            joined_at       TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(org_id, user_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS org_invites (
            id              SERIAL PRIMARY KEY,
            org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            email           TEXT NOT NULL,
            role            TEXT NOT NULL DEFAULT 'member',
            token           TEXT UNIQUE NOT NULL,
            invited_by      INTEGER NOT NULL REFERENCES users(id),
            accepted        BOOLEAN DEFAULT FALSE,
            expires_at      TIMESTAMPTZ NOT NULL,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_org_invites_token ON org_invites(token)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_org_invites_email ON org_invites(email)")

    # ── Notifications ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type            TEXT NOT NULL CHECK(type IN ('alert','scan_complete','invite','system')),
            title           TEXT NOT NULL,
            body            TEXT,
            link            TEXT,
            is_read         BOOLEAN DEFAULT FALSE,
            metadata        TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, is_read)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS notification_prefs (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            channel         TEXT NOT NULL CHECK(channel IN ('in_app','slack')),
            enabled         BOOLEAN DEFAULT TRUE,
            config          TEXT DEFAULT '{}',
            min_severity    TEXT DEFAULT 'medium' CHECK(min_severity IN ('critical','high','medium','low','info')),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(user_id, channel)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON notification_prefs(user_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS slack_configs (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            webhook_url     TEXT NOT NULL,
            channel_name    TEXT,
            is_active       BOOLEAN DEFAULT TRUE,
            last_sent       TIMESTAMPTZ,
            failure_count   INTEGER DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    # ── Reports ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            org_id          INTEGER REFERENCES organizations(id),
            title           TEXT NOT NULL,
            report_type     TEXT NOT NULL DEFAULT 'security' CHECK(report_type IN ('security','compliance','executive')),
            content         TEXT NOT NULL,
            format          TEXT DEFAULT 'json' CHECK(format IN ('json','html')),
            metadata        TEXT DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS report_schedules (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            report_type     TEXT NOT NULL DEFAULT 'security',
            frequency       TEXT NOT NULL CHECK(frequency IN ('daily','weekly','monthly')),
            last_generated  TIMESTAMPTZ,
            next_run        TIMESTAMPTZ,
            is_active       BOOLEAN DEFAULT TRUE,
            config          TEXT DEFAULT '{}',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_report_schedules_user ON report_schedules(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_report_schedules_next ON report_schedules(next_run)")

    # ── Integrations ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS integrations (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            org_id          INTEGER REFERENCES organizations(id),
            type            TEXT NOT NULL CHECK(type IN ('slack','jira')),
            name            TEXT NOT NULL,
            config          TEXT NOT NULL DEFAULT '{}',
            is_active       BOOLEAN DEFAULT TRUE,
            last_used       TIMESTAMPTZ,
            failure_count   INTEGER DEFAULT 0,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type)")

    # ── Compliance ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS compliance_frameworks (
            id              SERIAL PRIMARY KEY,
            name            TEXT UNIQUE NOT NULL,
            display_name    TEXT NOT NULL,
            version         TEXT,
            description     TEXT,
            controls        TEXT NOT NULL DEFAULT '[]',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS compliance_mappings (
            id              SERIAL PRIMARY KEY,
            framework_id    INTEGER NOT NULL REFERENCES compliance_frameworks(id),
            control_id      TEXT NOT NULL,
            control_name    TEXT NOT NULL,
            description     TEXT,
            check_type      TEXT NOT NULL CHECK(check_type IN ('bucket_status','file_classification','risk_level','sensitive_files','encryption')),
            check_config    TEXT DEFAULT '{}',
            severity        TEXT DEFAULT 'medium',
            UNIQUE(framework_id, control_id)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_compliance_mappings_framework ON compliance_mappings(framework_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS compliance_results (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id),
            framework_id    INTEGER NOT NULL REFERENCES compliance_frameworks(id),
            control_id      TEXT NOT NULL,
            status          TEXT NOT NULL CHECK(status IN ('pass','fail','partial','not_applicable')),
            evidence        TEXT,
            bucket_id       INTEGER REFERENCES buckets(id),
            checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_compliance_results_user ON compliance_results(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_compliance_results_framework ON compliance_results(framework_id)")

    # ── Remediations ──
    op.execute("""
        CREATE TABLE IF NOT EXISTS remediations (
            id              SERIAL PRIMARY KEY,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id),
            alert_id        INTEGER REFERENCES alerts(id),
            user_id         INTEGER NOT NULL REFERENCES users(id),
            assigned_to     INTEGER REFERENCES users(id),
            org_id          INTEGER REFERENCES organizations(id),
            status          TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','verified','closed')),
            priority        TEXT DEFAULT 'medium' CHECK(priority IN ('critical','high','medium','low')),
            title           TEXT NOT NULL,
            description     TEXT,
            due_date        TIMESTAMPTZ,
            completed_at    TIMESTAMPTZ,
            notes           TEXT DEFAULT '[]',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_user ON remediations(user_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_bucket ON remediations(bucket_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_assigned ON remediations(assigned_to)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_remediations_org ON remediations(org_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS remediations")
    op.execute("DROP TABLE IF EXISTS compliance_results")
    op.execute("DROP TABLE IF EXISTS compliance_mappings")
    op.execute("DROP TABLE IF EXISTS compliance_frameworks")
    op.execute("DROP TABLE IF EXISTS integrations")
    op.execute("DROP TABLE IF EXISTS report_schedules")
    op.execute("DROP TABLE IF EXISTS reports")
    op.execute("DROP TABLE IF EXISTS slack_configs")
    op.execute("DROP TABLE IF EXISTS notification_prefs")
    op.execute("DROP TABLE IF EXISTS notifications")
    op.execute("DROP TABLE IF EXISTS org_invites")
    op.execute("DROP TABLE IF EXISTS org_members")
    op.execute("DROP TABLE IF EXISTS organizations")
