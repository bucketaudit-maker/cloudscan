"""
Database layer — PostgreSQL (primary) with tsvector full-text search; SQLite for tests.
"""
import json
import logging
import os
import secrets
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from backend.app.config import settings
from backend.app.models.connection import get_db as _get_db

logger = logging.getLogger(__name__)


def _bool_sql(value: bool) -> str:
    """Return backend-compatible SQL literal for booleans."""
    if settings.is_postgres:
        return "TRUE" if value else "FALSE"
    return "1" if value else "0"

# ═══════════════════════════════════════════════════════════════════
# SCHEMA
# ═══════════════════════════════════════════════════════════════════

SCHEMA = """
CREATE TABLE IF NOT EXISTS providers (
    id          INTEGER PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    bucket_term TEXT NOT NULL,
    endpoint_pattern TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS buckets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id     INTEGER NOT NULL REFERENCES providers(id),
    name            TEXT NOT NULL,
    region          TEXT DEFAULT '',
    url             TEXT NOT NULL,
    status          TEXT DEFAULT 'unknown' CHECK(status IN ('open','closed','partial','error','unknown')),
    file_count      INTEGER DEFAULT 0,
    total_size_bytes INTEGER DEFAULT 0,
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_scanned    TEXT,
    last_status_check TEXT,
    scan_time_ms    INTEGER DEFAULT 0,
    metadata        TEXT,
    risk_score      INTEGER DEFAULT NULL,
    risk_level      TEXT DEFAULT NULL,
    company_name    TEXT DEFAULT NULL,
    UNIQUE(provider_id, name, region)
);

CREATE TABLE IF NOT EXISTS files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    filepath        TEXT NOT NULL,
    filename        TEXT NOT NULL,
    extension       TEXT DEFAULT '',
    size_bytes      INTEGER DEFAULT 0,
    last_modified   TEXT,
    etag            TEXT,
    content_type    TEXT DEFAULT '',
    url             TEXT NOT NULL,
    indexed_at      TEXT NOT NULL DEFAULT (datetime('now')),
    metadata        TEXT,
    ai_classification TEXT DEFAULT NULL,
    ai_confidence   REAL DEFAULT NULL,
    UNIQUE(bucket_id, filepath)
);

-- FTS5 full-text search index
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
    filepath, filename, extension, content_type,
    content=files, content_rowid=id,
    tokenize='porter unicode61'
);

-- Keep FTS in sync via triggers
CREATE TRIGGER IF NOT EXISTS trg_files_insert AFTER INSERT ON files BEGIN
    INSERT INTO files_fts(rowid, filepath, filename, extension, content_type)
    VALUES (new.id, new.filepath, new.filename, new.extension, new.content_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_files_delete AFTER DELETE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, filepath, filename, extension, content_type)
    VALUES ('delete', old.id, old.filepath, old.filename, old.extension, old.content_type);
END;

CREATE TRIGGER IF NOT EXISTS trg_files_update AFTER UPDATE ON files BEGIN
    INSERT INTO files_fts(files_fts, rowid, filepath, filename, extension, content_type)
    VALUES ('delete', old.id, old.filepath, old.filename, old.extension, old.content_type);
    INSERT INTO files_fts(rowid, filepath, filename, extension, content_type)
    VALUES (new.id, new.filepath, new.filename, new.extension, new.content_type);
END;

CREATE TABLE IF NOT EXISTS scan_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type        TEXT NOT NULL CHECK(job_type IN ('discovery','enumerate','rescan')),
    status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
    config          TEXT,
    progress        TEXT,
    started_at      TEXT,
    completed_at    TEXT,
    buckets_found   INTEGER DEFAULT 0,
    buckets_open    INTEGER DEFAULT 0,
    files_indexed   INTEGER DEFAULT 0,
    names_checked   INTEGER DEFAULT 0,
    errors          TEXT,
    created_by      INTEGER REFERENCES users(id),
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    tier            TEXT DEFAULT 'free' CHECK(tier IN ('free','premium','enterprise')),
    api_key         TEXT UNIQUE,
    is_active       BOOLEAN DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT,
    queries_today   INTEGER DEFAULT 0,
    queries_reset_at TEXT
);

CREATE TABLE IF NOT EXISTS api_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id),
    endpoint        TEXT NOT NULL,
    method          TEXT DEFAULT 'GET',
    query_params    TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    response_status INTEGER,
    response_time_ms INTEGER,
    created_at      TEXT DEFAULT (datetime('now'))
);

-- ═══ ATTACK SURFACE MONITORING ═══

CREATE TABLE IF NOT EXISTS watchlists (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id),
    name            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    keywords        TEXT NOT NULL,
    companies       TEXT DEFAULT '[]',
    providers       TEXT DEFAULT '[]',
    is_active       BOOLEAN DEFAULT 1,
    scan_interval_hours INTEGER DEFAULT 24,
    last_scan_at    TEXT,
    next_scan_at    TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id    INTEGER REFERENCES watchlists(id) ON DELETE CASCADE,
    user_id         INTEGER REFERENCES users(id),
    alert_type      TEXT NOT NULL CHECK(alert_type IN ('new_bucket','new_files','status_change','sensitive_file','bucket_closed')),
    severity        TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
    title           TEXT NOT NULL,
    description     TEXT,
    bucket_id       INTEGER REFERENCES buckets(id),
    file_id         INTEGER,
    is_read         BOOLEAN DEFAULT 0,
    is_resolved     BOOLEAN DEFAULT 0,
    resolved_at     TEXT,
    metadata        TEXT,
    ai_priority_score INTEGER DEFAULT NULL,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitored_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id    INTEGER REFERENCES watchlists(id) ON DELETE CASCADE,
    bucket_id       INTEGER REFERENCES buckets(id),
    first_detected  TEXT DEFAULT (datetime('now')),
    last_checked    TEXT,
    previous_status TEXT,
    current_status  TEXT,
    file_count_prev INTEGER DEFAULT 0,
    file_count_curr INTEGER DEFAULT 0,
    UNIQUE(watchlist_id, bucket_id)
);

CREATE TABLE IF NOT EXISTS webhook_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id),
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    secret          TEXT,
    event_types     TEXT DEFAULT '["critical","high"]',
    is_active       BOOLEAN DEFAULT 1,
    last_triggered  TEXT,
    failure_count   INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_watchlists_user ON watchlists(user_id);
CREATE INDEX IF NOT EXISTS idx_watchlists_next_scan ON watchlists(next_scan_at);
CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_watchlist ON alerts(watchlist_id);
CREATE INDEX IF NOT EXISTS idx_alerts_unread ON alerts(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_monitored_assets_wl ON monitored_assets(watchlist_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhook_configs(user_id);

CREATE TABLE IF NOT EXISTS saved_searches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    query_params    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_saved_searches_user ON saved_searches(user_id);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    token           TEXT UNIQUE NOT NULL,
    expires_at      TEXT NOT NULL,
    used            BOOLEAN DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_reset_tokens ON password_reset_tokens(token);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_buckets_provider ON buckets(provider_id);
CREATE INDEX IF NOT EXISTS idx_buckets_status ON buckets(status);
CREATE INDEX IF NOT EXISTS idx_buckets_name ON buckets(name);
CREATE INDEX IF NOT EXISTS idx_buckets_last_scanned ON buckets(last_scanned);
CREATE INDEX IF NOT EXISTS idx_files_bucket ON files(bucket_id);
CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension);
CREATE INDEX IF NOT EXISTS idx_files_filename ON files(filename);
CREATE INDEX IF NOT EXISTS idx_files_size ON files(size_bytes);
CREATE INDEX IF NOT EXISTS idx_files_indexed ON files(indexed_at);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_api_log_user ON api_log(user_id);
CREATE INDEX IF NOT EXISTS idx_api_log_created ON api_log(created_at);

-- AI feature indexes
CREATE INDEX IF NOT EXISTS idx_files_ai_classification ON files(ai_classification);
CREATE INDEX IF NOT EXISTS idx_buckets_risk_score ON buckets(risk_score);
CREATE INDEX IF NOT EXISTS idx_buckets_risk_level ON buckets(risk_level);
CREATE INDEX IF NOT EXISTS idx_alerts_ai_priority ON alerts(ai_priority_score);

-- ═══ Sprint 4: Team, Notifications, Reports, Integrations, Compliance, Remediation ═══

CREATE TABLE IF NOT EXISTS organizations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    slug            TEXT UNIQUE NOT NULL,
    owner_id        INTEGER NOT NULL REFERENCES users(id),
    api_key         TEXT UNIQUE,
    settings        TEXT DEFAULT '{}',
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS org_members (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','admin','member','viewer')),
    invited_by      INTEGER REFERENCES users(id),
    joined_at       TEXT DEFAULT (datetime('now')),
    UNIQUE(org_id, user_id)
);

CREATE TABLE IF NOT EXISTS org_invites (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id          INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'member',
    token           TEXT UNIQUE NOT NULL,
    invited_by      INTEGER NOT NULL REFERENCES users(id),
    accepted        BOOLEAN DEFAULT 0,
    expires_at      TEXT NOT NULL,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            TEXT NOT NULL CHECK(type IN ('alert','scan_complete','invite','system')),
    title           TEXT NOT NULL,
    body            TEXT,
    link            TEXT,
    is_read         BOOLEAN DEFAULT 0,
    metadata        TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notification_prefs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel         TEXT NOT NULL CHECK(channel IN ('in_app','slack')),
    enabled         BOOLEAN DEFAULT 1,
    config          TEXT DEFAULT '{}',
    min_severity    TEXT DEFAULT 'medium' CHECK(min_severity IN ('critical','high','medium','low','info')),
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, channel)
);

CREATE TABLE IF NOT EXISTS slack_configs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    webhook_url     TEXT NOT NULL,
    channel_name    TEXT,
    is_active       BOOLEAN DEFAULT 1,
    last_sent       TEXT,
    failure_count   INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id          INTEGER REFERENCES organizations(id),
    title           TEXT NOT NULL,
    report_type     TEXT NOT NULL DEFAULT 'security' CHECK(report_type IN ('security','compliance','executive')),
    content         TEXT NOT NULL,
    format          TEXT DEFAULT 'json' CHECK(format IN ('json','html')),
    metadata        TEXT DEFAULT '{}',
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS report_schedules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    report_type     TEXT NOT NULL DEFAULT 'security',
    frequency       TEXT NOT NULL CHECK(frequency IN ('daily','weekly','monthly')),
    last_generated  TEXT,
    next_run        TEXT,
    is_active       BOOLEAN DEFAULT 1,
    config          TEXT DEFAULT '{}',
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS integrations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id          INTEGER REFERENCES organizations(id),
    type            TEXT NOT NULL CHECK(type IN ('slack','jira')),
    name            TEXT NOT NULL,
    config          TEXT NOT NULL DEFAULT '{}',
    is_active       BOOLEAN DEFAULT 1,
    last_used       TEXT,
    failure_count   INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT UNIQUE NOT NULL,
    display_name    TEXT NOT NULL,
    version         TEXT,
    description     TEXT,
    controls        TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS compliance_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id    INTEGER NOT NULL REFERENCES compliance_frameworks(id),
    control_id      TEXT NOT NULL,
    control_name    TEXT NOT NULL,
    description     TEXT,
    check_type      TEXT NOT NULL CHECK(check_type IN ('bucket_status','file_classification','risk_level','sensitive_files','encryption')),
    check_config    TEXT DEFAULT '{}',
    severity        TEXT DEFAULT 'medium',
    UNIQUE(framework_id, control_id)
);

CREATE TABLE IF NOT EXISTS compliance_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    framework_id    INTEGER NOT NULL REFERENCES compliance_frameworks(id),
    control_id      TEXT NOT NULL,
    status          TEXT NOT NULL CHECK(status IN ('pass','fail','partial','not_applicable')),
    evidence        TEXT,
    bucket_id       INTEGER REFERENCES buckets(id),
    checked_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS remediations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id),
    alert_id        INTEGER REFERENCES alerts(id),
    user_id         INTEGER NOT NULL REFERENCES users(id),
    assigned_to     INTEGER REFERENCES users(id),
    org_id          INTEGER REFERENCES organizations(id),
    status          TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','verified','closed')),
    priority        TEXT DEFAULT 'medium' CHECK(priority IN ('critical','high','medium','low')),
    title           TEXT NOT NULL,
    description     TEXT,
    due_date        TEXT,
    completed_at    TEXT,
    notes           TEXT DEFAULT '[]',
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
);

-- Sprint 4 indexes
CREATE INDEX IF NOT EXISTS idx_org_members_org ON org_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_invites_token ON org_invites(token);
CREATE INDEX IF NOT EXISTS idx_org_invites_email ON org_invites(email);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_user ON notification_prefs(user_id);
CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
CREATE INDEX IF NOT EXISTS idx_report_schedules_user ON report_schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_report_schedules_next ON report_schedules(next_run);
CREATE INDEX IF NOT EXISTS idx_integrations_user ON integrations(user_id);
CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations(type);
CREATE INDEX IF NOT EXISTS idx_compliance_results_user ON compliance_results(user_id);
CREATE INDEX IF NOT EXISTS idx_compliance_results_framework ON compliance_results(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_mappings_framework ON compliance_mappings(framework_id);
CREATE INDEX IF NOT EXISTS idx_remediations_user ON remediations(user_id);
CREATE INDEX IF NOT EXISTS idx_remediations_bucket ON remediations(bucket_id);
CREATE INDEX IF NOT EXISTS idx_remediations_assigned ON remediations(assigned_to);
CREATE INDEX IF NOT EXISTS idx_remediations_status ON remediations(status);
CREATE INDEX IF NOT EXISTS idx_remediations_org ON remediations(org_id);

-- ═══ Sprint 5: Tags, Bookmarks, Scan Schedules, Audit Log ═══

CREATE TABLE IF NOT EXISTS tags (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    color       TEXT DEFAULT '#6b7280',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS bucket_tags (
    id          INTEGER PRIMARY KEY,
    bucket_id   INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    tag_id      INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(bucket_id, tag_id, user_id)
);

CREATE TABLE IF NOT EXISTS bookmarks (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bucket_id   INTEGER REFERENCES buckets(id) ON DELETE CASCADE,
    file_id     INTEGER,
    note        TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    keywords        TEXT NOT NULL DEFAULT '[]',
    companies       TEXT DEFAULT '[]',
    providers       TEXT DEFAULT '[]',
    frequency       TEXT NOT NULL DEFAULT 'daily' CHECK(frequency IN ('hourly','daily','weekly','monthly')),
    cron_expr       TEXT,
    is_active       BOOLEAN DEFAULT TRUE,
    last_run_at     TEXT,
    next_run_at     TEXT,
    last_job_id     INTEGER REFERENCES scan_jobs(id),
    config          TEXT DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,
    entity_type     TEXT,
    entity_id       INTEGER,
    details         TEXT,
    ip_address      TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Sprint 5 indexes
CREATE INDEX IF NOT EXISTS idx_bucket_tags_bucket ON bucket_tags(bucket_id);
CREATE INDEX IF NOT EXISTS idx_bucket_tags_tag ON bucket_tags(tag_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_user ON bookmarks(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_user ON scan_schedules(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next ON scan_schedules(next_run_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id);

-- ═══ Sprint 6: 2FA, Drift Detection, Alert Rules, CSRF, Dashboard ═══

-- Scan Snapshots (for drift detection)
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_job_id     INTEGER NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    status          TEXT NOT NULL,
    file_count      INTEGER DEFAULT 0,
    total_size_bytes INTEGER DEFAULT 0,
    file_hashes     TEXT DEFAULT '[]',
    captured_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(scan_job_id, bucket_id)
);

-- Scan Diffs
CREATE TABLE IF NOT EXISTS scan_diffs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    old_snapshot_id INTEGER REFERENCES scan_snapshots(id) ON DELETE SET NULL,
    new_snapshot_id INTEGER NOT NULL REFERENCES scan_snapshots(id) ON DELETE CASCADE,
    diff_type       TEXT NOT NULL CHECK(diff_type IN ('new_bucket','status_change','files_added','files_removed','size_change')),
    summary         TEXT NOT NULL,
    details         TEXT DEFAULT '{}',
    severity        TEXT DEFAULT 'info' CHECK(severity IN ('critical','high','medium','low','info')),
    is_reviewed     BOOLEAN DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Custom Alert Rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    is_active       BOOLEAN DEFAULT 1,
    conditions      TEXT NOT NULL DEFAULT '[]',
    actions         TEXT NOT NULL DEFAULT '["alert"]',
    severity        TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
    match_count     INTEGER DEFAULT 0,
    last_matched_at TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- CSRF Tokens
CREATE TABLE IF NOT EXISTS csrf_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT UNIQUE NOT NULL,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id      TEXT,
    expires_at      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Dashboard Stats Cache
CREATE TABLE IF NOT EXISTS dashboard_stats_cache (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    stat_type       TEXT NOT NULL,
    data            TEXT NOT NULL DEFAULT '{}',
    computed_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(user_id, stat_type)
);

-- Sprint 6 indexes
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_job ON scan_snapshots(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_bucket ON scan_snapshots(bucket_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_time ON scan_snapshots(captured_at);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_bucket ON scan_diffs(bucket_id);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_new_snap ON scan_diffs(new_snapshot_id);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_created ON scan_diffs(created_at);
CREATE INDEX IF NOT EXISTS idx_scan_diffs_severity ON scan_diffs(severity);
CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_csrf_tokens_token ON csrf_tokens(token);
CREATE INDEX IF NOT EXISTS idx_dashboard_cache_user ON dashboard_stats_cache(user_id);

-- Additional performance indexes
CREATE INDEX IF NOT EXISTS idx_files_bucket_ext ON files(bucket_id, extension);
CREATE INDEX IF NOT EXISTS idx_files_content_type ON files(content_type);
CREATE INDEX IF NOT EXISTS idx_files_last_modified ON files(last_modified);
CREATE INDEX IF NOT EXISTS idx_buckets_first_seen ON buckets(first_seen);
CREATE INDEX IF NOT EXISTS idx_buckets_status_provider ON buckets(status, provider_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(is_resolved);
CREATE INDEX IF NOT EXISTS idx_remediations_due ON remediations(due_date);
CREATE INDEX IF NOT EXISTS idx_remediations_completed ON remediations(completed_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_by ON scan_jobs(created_by);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_completed ON scan_jobs(completed_at);

-- ═══ Sprint 7: 20 New Features ═══

CREATE TABLE IF NOT EXISTS sensitive_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    file_id         INTEGER,
    filepath        TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'medium',
    compliance_controls TEXT DEFAULT '[]',
    scanned_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(bucket_id, filepath)
);

CREATE TABLE IF NOT EXISTS ticket_refs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform        TEXT NOT NULL DEFAULT 'jira',
    external_id     TEXT,
    title           TEXT NOT NULL,
    description     TEXT,
    priority        TEXT DEFAULT 'medium',
    status          TEXT DEFAULT 'created',
    bucket_id       INTEGER REFERENCES buckets(id),
    alert_id        INTEGER REFERENCES alerts(id),
    created_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at      TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_sf_bucket ON sensitive_findings(bucket_id);
CREATE INDEX IF NOT EXISTS idx_sf_severity ON sensitive_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sf_category ON sensitive_findings(category);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON ticket_refs(user_id);
CREATE INDEX IF NOT EXISTS idx_tickets_bucket ON ticket_refs(bucket_id);
"""

SEED_PROVIDERS = [
    (1, "aws", "Amazon Web Services", "bucket", "https://{name}.s3.{region}.amazonaws.com"),
    (2, "azure", "Microsoft Azure", "container", "https://{name}.blob.core.windows.net"),
    (3, "gcp", "Google Cloud Platform", "bucket", "https://storage.googleapis.com/{name}"),
    (4, "digitalocean", "DigitalOcean", "space", "https://{name}.{region}.digitaloceanspaces.com"),
    (5, "alibaba", "Alibaba Cloud", "bucket", "https://{name}.oss-{region}.aliyuncs.com"),
]


# ═══════════════════════════════════════════════════════════════════
# CONNECTION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

def get_db_path() -> str:
    return settings.db_path


def get_db():
    """Thread-safe database connection (PostgreSQL or SQLite). Use %s placeholders in SQL."""
    return _get_db()


def init_db() -> str:
    """Initialize database: Postgres = run migrations + seed providers; SQLite = create tables + seed."""
    if settings.is_postgres:
        backend_dir = Path(__file__).resolve().parent.parent.parent
        alembic_cmd = Path(sys.executable).with_name("alembic")
        if not alembic_cmd.exists():
            msg = (
                f"Alembic CLI not found at {alembic_cmd}. "
                "Install backend dependencies in this virtualenv "
                "(for example: pip install -r backend/requirements.txt)."
            )
            logger.error(msg)
            raise RuntimeError(msg)
        result = subprocess.run(
            [str(alembic_cmd), "upgrade", "head"],
            cwd=backend_dir,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.error(f"Alembic upgrade failed: {result.stderr}")
            raise RuntimeError(f"Migration failed: {result.stderr}")
        logger.info("PostgreSQL migrations applied")
        with _get_db() as db:
            for pid, name, display, term, pattern in SEED_PROVIDERS:
                db.execute(
                    "INSERT INTO providers (id,name,display_name,bucket_term,endpoint_pattern) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING",
                    (pid, name, display, term, pattern),
                )
        seed_compliance_frameworks()
        return settings.DATABASE_URL
    # SQLite
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    for pid, name, display, term, pattern in SEED_PROVIDERS:
        conn.execute(
            "INSERT OR IGNORE INTO providers (id,name,display_name,bucket_term,endpoint_pattern) VALUES (?,?,?,?,?)",
            (pid, name, display, term, pattern),
        )
    conn.commit()
    conn.close()
    seed_compliance_frameworks()
    logger.info(f"SQLite database initialized at {db_path}")
    return db_path


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — BUCKETS
# ═══════════════════════════════════════════════════════════════════

class BucketStore:
    @staticmethod
    def upsert(provider_id: int, name: str, region: str, url: str,
               status: str = "open", scan_time_ms: int = 0, metadata: dict = None,
               company_name: str = None) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            sql = """
                INSERT INTO buckets (provider_id, name, region, url, status, first_seen, last_scanned, scan_time_ms, metadata, company_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(provider_id, name, region) DO UPDATE SET
                    status=excluded.status, last_scanned=excluded.last_scanned,
                    scan_time_ms=excluded.scan_time_ms,
                    url=COALESCE(excluded.url, buckets.url),
                    metadata=COALESCE(excluded.metadata, buckets.metadata),
                    company_name=COALESCE(excluded.company_name, buckets.company_name)
            """ if settings.is_postgres else """
                INSERT INTO buckets (provider_id, name, region, url, status, first_seen, last_scanned, scan_time_ms, metadata, company_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(provider_id, name, region) DO UPDATE SET
                    status=excluded.status, last_scanned=excluded.last_scanned,
                    scan_time_ms=excluded.scan_time_ms,
                    url=COALESCE(excluded.url, url),
                    metadata=COALESCE(excluded.metadata, metadata),
                    company_name=COALESCE(excluded.company_name, company_name)
            """
            db.execute(sql, (provider_id, name, region, url, status, now, now, scan_time_ms,
                             json.dumps(metadata) if metadata else None, company_name))
            row = db.execute(
                "SELECT * FROM buckets WHERE provider_id=%s AND name=%s AND region=%s",
                (provider_id, name, region),
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get(bucket_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("""
                SELECT b.*, p.name as provider_name, p.display_name as provider_display
                FROM buckets b JOIN providers p ON b.provider_id=p.id WHERE b.id=%s
            """, (bucket_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_all(provider: str = None, status: str = None, search: str = None,
                 page: int = 1, per_page: int = 50, tag_id: int = None, tag_user_id: int = None) -> dict:
        with get_db() as db:
            q = """SELECT b.*, p.name as provider_name, p.display_name as provider_display
                   FROM buckets b JOIN providers p ON b.provider_id=p.id"""
            params = []
            if tag_id:
                q += " JOIN bucket_tags bt ON bt.bucket_id=b.id"
                q += " WHERE bt.tag_id=%s AND bt.user_id=%s"
                params.extend([tag_id, tag_user_id])
            else:
                q += " WHERE 1=1"
            if provider:
                q += " AND p.name=%s"; params.append(provider)
            if status:
                q += " AND b.status=%s"; params.append(status)
            if search:
                q += " AND b.name LIKE %s"; params.append(f"%{search}%")

            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY b.last_scanned DESC NULLS LAST LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def update_risk(bucket_id: int, risk_score: int, risk_level: str):
        with get_db() as db:
            db.execute(
                "UPDATE buckets SET risk_score=%s, risk_level=%s WHERE id=%s",
                (risk_score, risk_level, bucket_id),
            )

    @staticmethod
    def update_counts(bucket_id: int):
        with get_db() as db:
            r = db.execute(
                "SELECT COUNT(*) as cnt, COALESCE(SUM(size_bytes),0) as total FROM files WHERE bucket_id=%s",
                (bucket_id,),
            ).fetchone()
            db.execute(
                "UPDATE buckets SET file_count=%s, total_size_bytes=%s WHERE id=%s",
                (r["cnt"], r["total"], bucket_id),
            )


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — FILES
# ═══════════════════════════════════════════════════════════════════

class FileStore:
    @staticmethod
    def insert_batch(bucket_id: int, files_list: list[dict]) -> int:
        """Insert files in batch, returns count inserted."""
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            if settings.is_postgres:
                sql = """
                    INSERT INTO files
                    (bucket_id, filepath, filename, extension, size_bytes, last_modified, etag, content_type, url, indexed_at, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (bucket_id, filepath) DO NOTHING
                """
            else:
                sql = """
                    INSERT OR IGNORE INTO files
                    (bucket_id, filepath, filename, extension, size_bytes, last_modified, etag, content_type, url, indexed_at, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            db.executemany(sql, [(
                bucket_id, f["filepath"], f["filename"], f.get("extension", ""),
                f.get("size_bytes", 0), f.get("last_modified"), f.get("etag"),
                f.get("content_type", ""), f["url"], now,
                json.dumps(f.get("metadata")) if f.get("metadata") else None,
            ) for f in files_list])
            count = db.rowcount
        BucketStore.update_counts(bucket_id)
        return count

    @staticmethod
    def search(query: str = "", extensions: list = None, exclude_extensions: list = None,
               min_size: int = None, max_size: int = None, provider: str = None,
               bucket_name: str = None, sort: str = "relevance",
               page: int = 1, per_page: int = 50, regex: str = None,
               date_from: str = None, date_to: str = None) -> dict:
        import re
        with get_db() as db:
            base = """
                SELECT f.*, b.name as bucket_name, b.url as bucket_url, b.region,
                    p.name as provider_name, p.display_name as provider_display
                FROM files f
                JOIN buckets b ON f.bucket_id=b.id
                JOIN providers p ON b.provider_id=p.id
            """
            wheres, params = [], []

            if regex:
                if settings.is_postgres:
                    wheres.append("f.filepath ~ %s")
                else:
                    wheres.append("f.filepath REGEXP %s")
                params.append(regex)
            elif query:
                clean = re.sub(r'[^\w\s\-\*\.]', '', query)
                if settings.is_postgres:
                    wheres.append("f.search_vector @@ plainto_tsquery('english', %s)")
                    params.append(clean)
                else:
                    base += " JOIN files_fts ON files_fts.rowid=f.id"
                    fts_terms = []
                    for term in clean.split():
                        if not term:
                            continue
                        if term.startswith("-") and len(term) > 1:
                            fts_terms.append(f"NOT {term[1:]}")
                        elif term.startswith("*.") and len(term) > 2:
                            fts_terms.append(term[2:])
                        else:
                            fts_terms.append(f'"{term}"')
                    fts_q = " ".join(fts_terms) if fts_terms else '""'
                    wheres.append("files_fts MATCH %s")
                    params.append(fts_q)

            if extensions:
                ph = ",".join("%s" for _ in extensions)
                wheres.append(f"f.extension IN ({ph})")
                params.extend([e.lower().lstrip(".") for e in extensions if e])

            if exclude_extensions:
                ph = ",".join("%s" for _ in exclude_extensions)
                wheres.append(f"f.extension NOT IN ({ph})")
                params.extend([e.lower().lstrip(".") for e in exclude_extensions if e])

            if min_size is not None:
                wheres.append("f.size_bytes >= %s"); params.append(min_size)
            if max_size is not None:
                wheres.append("f.size_bytes <= %s"); params.append(max_size)
            if provider:
                wheres.append("p.name = %s"); params.append(provider)
            if bucket_name:
                wheres.append("b.name LIKE %s"); params.append(f"%{bucket_name}%")
            if date_from:
                wheres.append("f.last_modified >= %s"); params.append(date_from)
            if date_to:
                wheres.append("f.last_modified <= %s"); params.append(date_to)

            if wheres:
                base += " WHERE " + " AND ".join(wheres)

            total = db.execute(f"SELECT COUNT(*) FROM ({base})", tuple(params)).fetchone()[0]

            sort_map = {
                "relevance": "ORDER BY f.id DESC",
                "size_asc": "ORDER BY f.size_bytes ASC",
                "size_desc": "ORDER BY f.size_bytes DESC",
                "newest": "ORDER BY f.indexed_at DESC",
                "oldest": "ORDER BY f.indexed_at ASC",
                "filename": "ORDER BY f.filename ASC",
            }
            base += f" {sort_map.get(sort, 'ORDER BY f.id DESC')} LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])

            rows = db.execute(base, tuple(params)).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
                "query": query,
            }

    @staticmethod
    def update_classifications(bucket_id: int, classifications: list[dict]):
        """Update AI classifications for files in a bucket."""
        with get_db() as db:
            for c in classifications:
                db.execute(
                    "UPDATE files SET ai_classification=%s, ai_confidence=%s "
                    "WHERE bucket_id=%s AND filepath=%s",
                    (c.get("classification", "generic"),
                     c.get("confidence", 0.5),
                     bucket_id, c["filepath"]),
                )

    @staticmethod
    def get_classification_summary(bucket_id: int = None) -> dict:
        """Get classification counts, optionally filtered by bucket."""
        with get_db() as db:
            q = ("SELECT ai_classification, COUNT(*) as count FROM files "
                 "WHERE ai_classification IS NOT NULL")
            params = []
            if bucket_id:
                q += " AND bucket_id=%s"
                params.append(bucket_id)
            q += " GROUP BY ai_classification ORDER BY count DESC"
            rows = db.execute(q, tuple(params)).fetchall()
            return {r["ai_classification"]: r["count"] for r in rows}

    @staticmethod
    def get_stats() -> dict:
        with get_db() as db:
            s = {}
            s["total_files"] = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            s["total_buckets"] = db.execute("SELECT COUNT(*) FROM buckets").fetchone()[0]
            s["open_buckets"] = db.execute("SELECT COUNT(*) FROM buckets WHERE status='open'").fetchone()[0]
            s["total_size_bytes"] = db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM files").fetchone()[0]
            s["providers"] = [dict(r) for r in db.execute("""
                SELECT p.name, p.display_name, COUNT(b.id) as bucket_count,
                    COALESCE(SUM(b.file_count),0) as file_count
                FROM providers p LEFT JOIN buckets b ON p.id=b.provider_id
                GROUP BY p.id ORDER BY bucket_count DESC
            """).fetchall()]
            s["top_extensions"] = [dict(r) for r in db.execute("""
                SELECT extension, COUNT(*) as count FROM files
                WHERE extension != '' GROUP BY extension ORDER BY count DESC LIMIT 20
            """).fetchall()]
            s["recent_buckets"] = [dict(r) for r in db.execute("""
                SELECT b.*, p.name as provider_name FROM buckets b
                JOIN providers p ON b.provider_id=p.id
                WHERE b.status='open' ORDER BY b.last_scanned DESC LIMIT 10
            """).fetchall()]
            return s

    @staticmethod
    def get_timeline(days: int = 30) -> dict:
        with get_db() as db:
            if settings.is_postgres:
                files_tl = [dict(r) for r in db.execute("""
                    SELECT indexed_at::date::text as day, COUNT(*) as count
                    FROM files WHERE indexed_at >= NOW() - INTERVAL '%s days'
                    GROUP BY indexed_at::date ORDER BY day
                """ % days).fetchall()]
                buckets_tl = [dict(r) for r in db.execute("""
                    SELECT first_seen::date::text as day, COUNT(*) as count
                    FROM buckets WHERE first_seen >= NOW() - INTERVAL '%s days'
                    GROUP BY first_seen::date ORDER BY day
                """ % days).fetchall()]
            else:
                cutoff = f"-{days} days"
                files_tl = [dict(r) for r in db.execute("""
                    SELECT date(indexed_at) as day, COUNT(*) as count
                    FROM files WHERE indexed_at >= datetime('now', %s)
                    GROUP BY date(indexed_at) ORDER BY day
                """, (cutoff,)).fetchall()]
                buckets_tl = [dict(r) for r in db.execute("""
                    SELECT date(first_seen) as day, COUNT(*) as count
                    FROM buckets WHERE first_seen >= datetime('now', %s)
                    GROUP BY date(first_seen) ORDER BY day
                """, (cutoff,)).fetchall()]
            return {
                "files_timeline": files_tl,
                "buckets_timeline": buckets_tl,
                "days": days,
            }

    @staticmethod
    def get_breakdown() -> dict:
        with get_db() as db:
            risk = [dict(r) for r in db.execute("""
                SELECT risk_level, COUNT(*) as count FROM buckets
                WHERE risk_level IS NOT NULL GROUP BY risk_level
            """).fetchall()]
            providers = [dict(r) for r in db.execute("""
                SELECT p.name, p.display_name, COUNT(b.id) as bucket_count,
                    COALESCE(SUM(b.file_count),0) as file_count
                FROM providers p LEFT JOIN buckets b ON p.id=b.provider_id
                GROUP BY p.id ORDER BY bucket_count DESC
            """).fetchall()]
            classifications = [dict(r) for r in db.execute("""
                SELECT ai_classification, COUNT(*) as count FROM files
                WHERE ai_classification IS NOT NULL
                GROUP BY ai_classification ORDER BY count DESC
            """).fetchall()]
            statuses = [dict(r) for r in db.execute("""
                SELECT status, COUNT(*) as count FROM buckets
                GROUP BY status ORDER BY count DESC
            """).fetchall()]
            extensions = [dict(r) for r in db.execute("""
                SELECT extension, COUNT(*) as count FROM files
                WHERE extension != '' GROUP BY extension ORDER BY count DESC LIMIT 15
            """).fetchall()]
            return {
                "risk_distribution": risk,
                "provider_distribution": providers,
                "classification_distribution": classifications,
                "status_distribution": statuses,
                "extension_distribution": extensions,
            }


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — SCAN JOBS
# ═══════════════════════════════════════════════════════════════════

class ScanJobStore:
    @staticmethod
    def create(job_type: str, config: dict, created_by: int = None) -> dict:
        with get_db() as db:
            db.execute("""
                INSERT INTO scan_jobs (job_type, status, config, created_by)
                VALUES (%s, 'pending', %s, %s)
            """, (job_type, json.dumps(config), created_by))
            row = db.execute("SELECT * FROM scan_jobs WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row)

    @staticmethod
    def get(job_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("SELECT * FROM scan_jobs WHERE id=%s", (job_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(job_id: int, **kwargs):
        with get_db() as db:
            sets = ", ".join(f"{k}=%s" for k in kwargs)
            vals = list(kwargs.values())
            vals.append(job_id)
            db.execute(f"UPDATE scan_jobs SET {sets} WHERE id=%s", tuple(vals))

    @staticmethod
    def list_recent(limit: int = 50) -> list[dict]:
        with get_db() as db:
            rows = db.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT %s", (limit,)).fetchall()
            return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — WATCHLISTS & MONITORING
# ═══════════════════════════════════════════════════════════════════

SENSITIVE_PATTERNS = [
    ".env", "credentials", "secret", "password", "api_key", "apikey",
    "token", "private_key", "id_rsa", ".pem", ".key", ".pfx",
    "terraform.tfstate", "wp-config", ".htpasswd", "shadow",
    "master.key", "database.yml", "configuration.yml",
    "backup.sql", "dump.sql", ".sql.gz", "firebase", "gcp-key",
    "aws-credentials", "oauth", ".p12", "keystore",
]


class WatchlistStore:
    @staticmethod
    def create(user_id: int, name: str, keywords: list, companies: list = None,
               providers: list = None, scan_interval_hours: int = 24) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_scan = (datetime.now(timezone.utc) + timedelta(hours=scan_interval_hours)).isoformat()
            db.execute("""
                INSERT INTO watchlists (user_id, name, keywords, companies, providers,
                    scan_interval_hours, next_scan_at, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, name, json.dumps(keywords), json.dumps(companies or []),
                  json.dumps(providers or []), scan_interval_hours, next_scan, now, now))
            return dict(db.execute("SELECT * FROM watchlists WHERE id=%s", (db.lastrowid,)).fetchone())

    @staticmethod
    def get(wl_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("SELECT * FROM watchlists WHERE id=%s", (wl_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_by_user(user_id: int = None) -> list[dict]:
        with get_db() as db:
            if user_id:
                rows = db.execute("SELECT * FROM watchlists WHERE user_id=%s ORDER BY created_at DESC", (user_id,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM watchlists ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def list_due() -> list[dict]:
        """Get watchlists due for scanning."""
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            rows = db.execute(
                f"SELECT * FROM watchlists WHERE is_active={_bool_sql(True)} AND (next_scan_at IS NULL OR next_scan_at <= %s)",
                (now,)
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def update(wl_id: int, **kwargs):
        with get_db() as db:
            kwargs["updated_at"] = datetime.now(timezone.utc).isoformat()
            sets = ", ".join(f"{k}=%s" for k in kwargs)
            vals = list(kwargs.values()) + [wl_id]
            db.execute(f"UPDATE watchlists SET {sets} WHERE id=%s", tuple(vals))

    @staticmethod
    def delete(wl_id: int):
        with get_db() as db:
            db.execute("DELETE FROM watchlists WHERE id=%s", (wl_id,))

    @staticmethod
    def mark_scanned(wl_id: int, interval_hours: int = 24):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_scan = (datetime.now(timezone.utc) + timedelta(hours=interval_hours)).isoformat()
            db.execute("UPDATE watchlists SET last_scan_at=%s, next_scan_at=%s, updated_at=%s WHERE id=%s",
                       (now, next_scan, now, wl_id))

    @staticmethod
    def get_dashboard(user_id=None) -> dict:
        with get_db() as db:
            wl_count = db.execute("SELECT COUNT(*) FROM watchlists WHERE user_id=%s", (user_id,)).fetchone()[0]
            alert_counts = db.execute("""
                SELECT severity, COUNT(*) as cnt FROM alerts
                WHERE user_id=%s AND is_resolved=""" + _bool_sql(False) + """
                GROUP BY severity
            """, (user_id,)).fetchall()
            unread = db.execute(
                "SELECT COUNT(*) FROM alerts WHERE user_id=%s AND is_read=" + _bool_sql(False),
                (user_id,),
            ).fetchone()[0]
            monitored = db.execute("""
                SELECT COUNT(DISTINCT ma.bucket_id) FROM monitored_assets ma
                JOIN watchlists w ON ma.watchlist_id=w.id WHERE w.user_id=%s
            """, (user_id,)).fetchone()[0]
            return {
                "watchlists": wl_count,
                "monitored_buckets": monitored,
                "unread_alerts": unread,
                "alerts_by_severity": {r["severity"]: r["cnt"] for r in alert_counts},
            }


class AlertStore:
    @staticmethod
    def create(watchlist_id: int, user_id: int, alert_type: str, severity: str,
               title: str, description: str = "", bucket_id: int = None,
               file_id: int = None, metadata: dict = None) -> dict:
        with get_db() as db:
            db.execute("""
                INSERT INTO alerts (watchlist_id, user_id, alert_type, severity,
                    title, description, bucket_id, file_id, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (watchlist_id, user_id, alert_type, severity, title, description,
                  bucket_id, file_id, json.dumps(metadata) if metadata else None))
            return dict(db.execute("SELECT * FROM alerts WHERE id=%s", (db.lastrowid,)).fetchone())

    @staticmethod
    def get_for_user(alert_id: int, user_id: int) -> Optional[dict]:
        """Fetch an alert only if it belongs to the given user (for ownership checks)."""
        if user_id is None:
            return None
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM alerts WHERE id=%s AND user_id=%s", (alert_id, user_id)
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_by_user(user_id=None, unread_only: bool = False, severity: str = None,
                     page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            q = """SELECT a.*, w.name as watchlist_name, b.name as bucket_name, b.url as bucket_url,
                   p.name as provider_name
                   FROM alerts a
                   LEFT JOIN watchlists w ON a.watchlist_id=w.id
                   LEFT JOIN buckets b ON a.bucket_id=b.id
                   LEFT JOIN providers p ON b.provider_id=p.id
                   WHERE a.user_id=%s"""
            params = [user_id]
            if unread_only:
                q += f" AND a.is_read={_bool_sql(False)}"
            if severity:
                q += " AND a.severity=%s"
                params.append(severity)
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY a.created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page}

    @staticmethod
    def mark_read(alert_id: int, user_id: int):
        with get_db() as db:
            db.execute("UPDATE alerts SET is_read=%s WHERE id=%s AND user_id=%s", (True, alert_id, user_id))

    @staticmethod
    def mark_all_read(user_id: int):
        with get_db() as db:
            db.execute(
                f"UPDATE alerts SET is_read={_bool_sql(True)} WHERE user_id=%s AND is_read={_bool_sql(False)}",
                (user_id,),
            )

    @staticmethod
    def resolve(alert_id: int, user_id: int):
        with get_db() as db:
            db.execute("UPDATE alerts SET is_resolved=1, resolved_at=%s WHERE id=%s AND user_id=%s",
                       (datetime.now(timezone.utc).isoformat(), alert_id, user_id))

    @staticmethod
    def detect_sensitive_files(bucket_id: int, files: list[dict]) -> list[dict]:
        """Check files against sensitive patterns, return matches with severity."""
        findings = []
        for f in files:
            fp = f.get("filepath", "").lower()
            fn = f.get("filename", "").lower()
            for pattern in SENSITIVE_PATTERNS:
                if pattern in fp or pattern in fn:
                    sev = "critical" if pattern in (".env", "credentials", "id_rsa", "private_key", ".key", "terraform.tfstate", "master.key") else "high"
                    findings.append({
                        "file": f, "pattern": pattern, "severity": sev,
                        "title": f"Sensitive file exposed: {f.get('filename', '')}",
                    })
                    break
        return findings


class MonitoredAssetStore:
    @staticmethod
    def upsert(watchlist_id: int, bucket_id: int, status: str, file_count: int) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            existing = db.execute(
                "SELECT * FROM monitored_assets WHERE watchlist_id=%s AND bucket_id=%s",
                (watchlist_id, bucket_id)
            ).fetchone()

            if existing:
                db.execute("""
                    UPDATE monitored_assets SET
                        previous_status=current_status, current_status=%s,
                        file_count_prev=file_count_curr, file_count_curr=%s,
                        last_checked=%s
                    WHERE watchlist_id=%s AND bucket_id=%s
                """, (status, file_count, now, watchlist_id, bucket_id))
            else:
                db.execute("""
                    INSERT INTO monitored_assets (watchlist_id, bucket_id, current_status,
                        file_count_curr, first_detected, last_checked)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (watchlist_id, bucket_id, status, file_count, now, now))

            row = db.execute(
                "SELECT * FROM monitored_assets WHERE watchlist_id=%s AND bucket_id=%s",
                (watchlist_id, bucket_id)
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_watchlist(watchlist_id: int) -> list[dict]:
        with get_db() as db:
            rows = db.execute("""
                SELECT ma.*, b.name as bucket_name, b.url as bucket_url, b.region,
                    p.name as provider_name, p.display_name as provider_display
                FROM monitored_assets ma
                JOIN buckets b ON ma.bucket_id=b.id
                JOIN providers p ON b.provider_id=p.id
                WHERE ma.watchlist_id=%s
                ORDER BY ma.first_detected DESC
            """, (watchlist_id,)).fetchall()
            return [dict(r) for r in rows]


class WebhookStore:
    @staticmethod
    def create(user_id: int, name: str, url: str, secret: str = None,
               event_types: list = None) -> dict:
        if event_types is None:
            event_types = ["critical", "high"]
        with get_db() as db:
            db.execute(
                "INSERT INTO webhook_configs (user_id, name, url, secret, event_types) VALUES (%s, %s, %s, %s, %s)",
                (user_id, name, url, secret, json.dumps(event_types)),
            )
            row = db.execute(
                "SELECT * FROM webhook_configs WHERE id=%s", (db.lastrowid,)
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id: int) -> list:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM webhook_configs WHERE user_id=%s ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get(webhook_id: int, user_id: int) -> dict | None:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM webhook_configs WHERE id=%s AND user_id=%s",
                (webhook_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(webhook_id: int, user_id: int, **kwargs) -> bool:
        allowed = {"name", "url", "secret", "event_types", "is_active"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                if k == "event_types":
                    v = json.dumps(v)
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        params.extend([webhook_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE webhook_configs SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(webhook_id: int, user_id: int) -> bool:
        with get_db() as db:
            db.execute(
                "DELETE FROM webhook_configs WHERE id=%s AND user_id=%s",
                (webhook_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def get_active_for_user(user_id: int) -> list:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM webhook_configs WHERE user_id=%s AND is_active=%s",
                (user_id, True),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def increment_failure(webhook_id: int):
        with get_db() as db:
            db.execute(
                "UPDATE webhook_configs SET failure_count=failure_count+1 WHERE id=%s",
                (webhook_id,),
            )
            row = db.execute(
                "SELECT failure_count FROM webhook_configs WHERE id=%s", (webhook_id,)
            ).fetchone()
            if row and row["failure_count"] >= 10:
                db.execute(
                    "UPDATE webhook_configs SET is_active=%s WHERE id=%s", (False, webhook_id)
                )

    @staticmethod
    def reset_failure(webhook_id: int):
        with get_db() as db:
            db.execute(
                "UPDATE webhook_configs SET failure_count=0 WHERE id=%s", (webhook_id,)
            )

    @staticmethod
    def mark_triggered(webhook_id: int):
        with get_db() as db:
            db.execute(
                "UPDATE webhook_configs SET last_triggered=datetime('now') WHERE id=%s",
                (webhook_id,),
            )


class SavedSearchStore:
    @staticmethod
    def create(user_id: int, name: str, query_params: dict) -> dict:
        with get_db() as db:
            db.execute(
                "INSERT INTO saved_searches (user_id, name, query_params) VALUES (%s, %s, %s)",
                (user_id, name, json.dumps(query_params)),
            )
            row = db.execute(
                "SELECT * FROM saved_searches WHERE id=%s", (db.lastrowid,)
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id: int) -> list:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM saved_searches WHERE user_id=%s ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def delete(search_id: int, user_id: int) -> bool:
        with get_db() as db:
            db.execute(
                "DELETE FROM saved_searches WHERE id=%s AND user_id=%s",
                (search_id, user_id),
            )
            return db.rowcount > 0


class ApiLogStore:
    @staticmethod
    def log(user_id: int, endpoint: str, method: str, query_params: str,
            ip_address: str, user_agent: str, response_status: int,
            response_time_ms: int):
        try:
            with get_db() as db:
                db.execute("""
                    INSERT INTO api_log
                        (user_id, endpoint, method, query_params, ip_address,
                         user_agent, response_status, response_time_ms)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (user_id, endpoint, method, query_params, ip_address,
                      user_agent, response_status, response_time_ms))
        except Exception as e:
            logger.debug(f"Failed to log API request: {e}")

    @staticmethod
    def list_by_user(user_id: int, page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            total = db.execute(
                "SELECT COUNT(*) FROM api_log WHERE user_id=%s", (user_id,)
            ).fetchone()[0]
            rows = db.execute(
                """SELECT id, endpoint, method, query_params, ip_address,
                          response_status, response_time_ms, created_at
                   FROM api_log WHERE user_id=%s
                   ORDER BY created_at DESC LIMIT %s OFFSET %s""",
                (user_id, per_page, (page - 1) * per_page),
            ).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
            }


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — ORGANIZATIONS & TEAMS
# ═══════════════════════════════════════════════════════════════════

class OrgStore:
    @staticmethod
    def create(owner_id, name, slug):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            api_key = f"org_{secrets.token_hex(24)}"
            db.execute("""
                INSERT INTO organizations (name, slug, owner_id, api_key, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (name, slug, owner_id, api_key, now, now))
            org_id = db.lastrowid
            db.execute("""
                INSERT INTO org_members (org_id, user_id, role, joined_at)
                VALUES (%s, %s, 'owner', %s)
            """, (org_id, owner_id, now))
            row = db.execute("SELECT * FROM organizations WHERE id=%s", (org_id,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get(org_id):
        with get_db() as db:
            row = db.execute("SELECT * FROM organizations WHERE id=%s", (org_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_by_slug(slug):
        with get_db() as db:
            row = db.execute("SELECT * FROM organizations WHERE slug=%s", (slug,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_for_user(user_id):
        with get_db() as db:
            rows = db.execute("""
                SELECT o.* FROM organizations o
                JOIN org_members m ON o.id=m.org_id
                WHERE m.user_id=%s ORDER BY o.name
            """, (user_id,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_members(org_id):
        with get_db() as db:
            rows = db.execute("""
                SELECT m.*, u.email, u.username
                FROM org_members m JOIN users u ON m.user_id=u.id
                WHERE m.org_id=%s ORDER BY m.joined_at
            """, (org_id,)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def add_member(org_id, user_id, role='member', invited_by=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO org_members (org_id, user_id, role, invited_by, joined_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (org_id, user_id, role, invited_by, now))

    @staticmethod
    def remove_member(org_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM org_members WHERE org_id=%s AND user_id=%s AND role != 'owner'",
                (org_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def update_role(org_id, user_id, role):
        with get_db() as db:
            db.execute(
                "UPDATE org_members SET role=%s WHERE org_id=%s AND user_id=%s",
                (role, org_id, user_id),
            )

    @staticmethod
    def create_invite(org_id, email, role, invited_by):
        with get_db() as db:
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO org_invites (org_id, email, role, token, invited_by, expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (org_id, email, role, token, invited_by, expires_at, now))
            row = db.execute("SELECT * FROM org_invites WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def accept_invite(token, user_id):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            row = db.execute(
                "SELECT * FROM org_invites WHERE token=%s AND accepted=%s AND expires_at > %s",
                (token, False, now),
            ).fetchone()
            if not row:
                return None
            invite = dict(row)
            db.execute("UPDATE org_invites SET accepted=%s WHERE id=%s", (True, invite["id"]))
            OrgStore.add_member(invite["org_id"], user_id, invite["role"], invite["invited_by"])
            return OrgStore.get(invite["org_id"])

    @staticmethod
    def get_pending_invites(org_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM org_invites WHERE org_id=%s AND accepted=%s ORDER BY created_at DESC",
                (org_id, False),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def check_permission(org_id, user_id, min_role='viewer'):
        ROLE_LEVEL = {'viewer': 0, 'member': 1, 'admin': 2, 'owner': 3}
        with get_db() as db:
            row = db.execute(
                "SELECT role FROM org_members WHERE org_id=%s AND user_id=%s",
                (org_id, user_id),
            ).fetchone()
            if not row:
                return False
            return ROLE_LEVEL.get(row["role"], 0) >= ROLE_LEVEL.get(min_role, 0)


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════════

class NotificationStore:
    @staticmethod
    def create(user_id, type, title, body=None, link=None, metadata=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO notifications (user_id, type, title, body, link, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, type, title, body, link,
                  json.dumps(metadata) if isinstance(metadata, dict) else metadata, now))
            row = db.execute("SELECT * FROM notifications WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id, unread_only=False, page=1, per_page=20):
        with get_db() as db:
            q = "SELECT * FROM notifications WHERE user_id=%s"
            params = [user_id]
            if unread_only:
                q += " AND is_read=%s"
                params.append(False)
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    @staticmethod
    def mark_read(notif_id, user_id):
        with get_db() as db:
            db.execute(
                "UPDATE notifications SET is_read=%s WHERE id=%s AND user_id=%s",
                (True, notif_id, user_id),
            )

    @staticmethod
    def mark_all_read(user_id):
        with get_db() as db:
            db.execute(
                "UPDATE notifications SET is_read=%s WHERE user_id=%s AND is_read=%s",
                (True, user_id, False),
            )
            return db.rowcount

    @staticmethod
    def unread_count(user_id):
        with get_db() as db:
            return db.execute(
                "SELECT COUNT(*) FROM notifications WHERE user_id=%s AND is_read=%s",
                (user_id, False),
            ).fetchone()[0]


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — NOTIFICATION PREFERENCES
# ═══════════════════════════════════════════════════════════════════

class NotificationPrefStore:
    @staticmethod
    def get_for_user(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM notification_prefs WHERE user_id=%s",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def upsert(user_id, channel, enabled=True, config=None, min_severity='medium'):
        with get_db() as db:
            config_str = json.dumps(config) if isinstance(config, dict) else (config or '{}')
            enabled_val = True if enabled else False
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO notification_prefs (user_id, channel, enabled, config, min_severity, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT(user_id, channel) DO UPDATE SET
                    enabled=excluded.enabled,
                    config=excluded.config,
                    min_severity=excluded.min_severity
            """, (user_id, channel, enabled_val, config_str, min_severity, now))
            row = db.execute(
                "SELECT * FROM notification_prefs WHERE user_id=%s AND channel=%s",
                (user_id, channel),
            ).fetchone()
            return dict(row) if row else {}


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — SLACK CONFIGS
# ═══════════════════════════════════════════════════════════════════

class SlackConfigStore:
    @staticmethod
    def create(user_id, webhook_url, channel_name=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO slack_configs (user_id, webhook_url, channel_name, created_at)
                VALUES (%s, %s, %s, %s)
            """, (user_id, webhook_url, channel_name, now))
            row = db.execute("SELECT * FROM slack_configs WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get_for_user(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM slack_configs WHERE user_id=%s AND is_active=%s",
                (user_id, True),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def update(config_id, user_id, **kwargs):
        allowed = {"webhook_url", "channel_name", "is_active"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        params.extend([config_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE slack_configs SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(config_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM slack_configs WHERE id=%s AND user_id=%s",
                (config_id, user_id),
            )
            return db.rowcount > 0


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — REPORTS
# ═══════════════════════════════════════════════════════════════════

class ReportStore:
    @staticmethod
    def create(user_id, title, report_type, content, format='json', org_id=None, metadata=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            metadata_str = json.dumps(metadata) if isinstance(metadata, dict) else (metadata or '{}')
            db.execute("""
                INSERT INTO reports (user_id, org_id, title, report_type, content, format, metadata, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, org_id, title, report_type, content, format, metadata_str, now))
            row = db.execute("SELECT * FROM reports WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id, page=1, per_page=20):
        with get_db() as db:
            total = db.execute(
                "SELECT COUNT(*) FROM reports WHERE user_id=%s", (user_id,)
            ).fetchone()[0]
            rows = db.execute("""
                SELECT id, user_id, org_id, title, report_type, format, metadata, created_at
                FROM reports WHERE user_id=%s
                ORDER BY created_at DESC LIMIT %s OFFSET %s
            """, (user_id, per_page, (page - 1) * per_page)).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    @staticmethod
    def get(report_id, user_id):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM reports WHERE id=%s AND user_id=%s",
                (report_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def delete(report_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM reports WHERE id=%s AND user_id=%s",
                (report_id, user_id),
            )
            return db.rowcount > 0


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — REPORT SCHEDULES
# ═══════════════════════════════════════════════════════════════════

class ReportScheduleStore:
    @staticmethod
    def _compute_next_run(frequency):
        """Compute the next run time based on frequency."""
        now = datetime.now(timezone.utc)
        if frequency == 'daily':
            next_run = (now + timedelta(days=1)).replace(hour=6, minute=0, second=0, microsecond=0)
        elif frequency == 'weekly':
            days_ahead = 7 - now.weekday()  # Monday is 0
            if days_ahead == 0:
                days_ahead = 7
            next_run = (now + timedelta(days=days_ahead)).replace(hour=6, minute=0, second=0, microsecond=0)
        elif frequency == 'monthly':
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=1, hour=6, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(month=now.month + 1, day=1, hour=6, minute=0, second=0, microsecond=0)
        else:
            next_run = now + timedelta(days=1)
        return next_run.isoformat()

    @staticmethod
    def create(user_id, report_type, frequency, config=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_run = ReportScheduleStore._compute_next_run(frequency)
            config_str = json.dumps(config) if isinstance(config, dict) else (config or '{}')
            db.execute("""
                INSERT INTO report_schedules (user_id, report_type, frequency, next_run, config, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, report_type, frequency, next_run, config_str, now))
            row = db.execute("SELECT * FROM report_schedules WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM report_schedules WHERE user_id=%s ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def update(schedule_id, user_id, **kwargs):
        allowed = {"frequency", "is_active", "config", "report_type"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                if k == "config" and isinstance(v, dict):
                    v = json.dumps(v)
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        params.extend([schedule_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE report_schedules SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(schedule_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM report_schedules WHERE id=%s AND user_id=%s",
                (schedule_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def list_due():
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            rows = db.execute(
                "SELECT * FROM report_schedules WHERE is_active=%s AND (next_run IS NULL OR next_run <= %s)",
                (True, now),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def mark_generated(schedule_id, frequency):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_run = ReportScheduleStore._compute_next_run(frequency)
            db.execute(
                "UPDATE report_schedules SET last_generated=%s, next_run=%s WHERE id=%s",
                (now, next_run, schedule_id),
            )


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════

class IntegrationStore:
    @staticmethod
    def create(user_id, type, name, config, org_id=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            config_str = json.dumps(config) if isinstance(config, dict) else config
            db.execute("""
                INSERT INTO integrations (user_id, org_id, type, name, config, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, org_id, type, name, config_str, now, now))
            row = db.execute("SELECT * FROM integrations WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id, type=None):
        with get_db() as db:
            if type:
                rows = db.execute(
                    "SELECT * FROM integrations WHERE user_id=%s AND type=%s ORDER BY created_at DESC",
                    (user_id, type),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM integrations WHERE user_id=%s ORDER BY created_at DESC",
                    (user_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get(integration_id, user_id):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM integrations WHERE id=%s AND user_id=%s",
                (integration_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(integration_id, user_id, **kwargs):
        allowed = {"name", "config", "is_active"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                if k == "config" and isinstance(v, dict):
                    v = json.dumps(v)
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at=%s")
        params.append(now)
        params.extend([integration_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE integrations SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(integration_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM integrations WHERE id=%s AND user_id=%s",
                (integration_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def get_active_by_type(user_id, type):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM integrations WHERE user_id=%s AND type=%s AND is_active=%s",
                (user_id, type, True),
            ).fetchall()
            return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — COMPLIANCE
# ═══════════════════════════════════════════════════════════════════

class ComplianceStore:
    @staticmethod
    def list_frameworks():
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM compliance_frameworks ORDER BY name"
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_framework(framework_id):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM compliance_frameworks WHERE id=%s",
                (framework_id,),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_mappings(framework_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM compliance_mappings WHERE framework_id=%s ORDER BY control_id",
                (framework_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def run_check(user_id, framework_id):
        mappings = ComplianceStore.get_mappings(framework_id)
        results = []
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            for mapping in mappings:
                check_type = mapping["check_type"]
                check_config = json.loads(mapping["check_config"]) if mapping.get("check_config") else {}
                control_id = mapping["control_id"]
                status = "pass"
                evidence = None

                if check_type == "bucket_status":
                    count = db.execute(
                        "SELECT COUNT(*) FROM buckets WHERE status='open'"
                    ).fetchone()[0]
                    if count > 0:
                        status = "fail"
                        evidence = json.dumps({"open_buckets": count})

                elif check_type == "file_classification":
                    target = check_config.get("classification", "credentials")
                    count = db.execute(
                        "SELECT COUNT(*) FROM files WHERE ai_classification=%s",
                        (target,),
                    ).fetchone()[0]
                    if count > 0:
                        status = "fail"
                        evidence = json.dumps({"classification": target, "count": count})

                elif check_type == "risk_level":
                    count = db.execute(
                        "SELECT COUNT(*) FROM buckets WHERE risk_level='critical'"
                    ).fetchone()[0]
                    if count > 0:
                        status = "fail"
                        evidence = json.dumps({"critical_buckets": count})

                elif check_type == "sensitive_files":
                    count = db.execute(
                        "SELECT COUNT(*) FROM files WHERE ai_classification IN ('credentials','pii','financial','medical')"
                    ).fetchone()[0]
                    if count > 0:
                        status = "fail"
                        evidence = json.dumps({"sensitive_files": count})

                elif check_type == "encryption":
                    status = "pass"
                    evidence = json.dumps({"note": "Cloud providers enforce TLS in transit"})

                # Insert or replace result
                existing = db.execute(
                    "SELECT id FROM compliance_results WHERE user_id=%s AND framework_id=%s AND control_id=%s",
                    (user_id, framework_id, control_id),
                ).fetchone()
                if existing:
                    db.execute("""
                        UPDATE compliance_results SET status=%s, evidence=%s, checked_at=%s
                        WHERE id=%s
                    """, (status, evidence, now, existing["id"]))
                else:
                    db.execute("""
                        INSERT INTO compliance_results (user_id, framework_id, control_id, status, evidence, checked_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (user_id, framework_id, control_id, status, evidence, now))

                results.append({
                    "control_id": control_id,
                    "control_name": mapping["control_name"],
                    "status": status,
                    "evidence": evidence,
                    "severity": mapping.get("severity", "medium"),
                })
        return results

    @staticmethod
    def get_results(user_id, framework_id):
        with get_db() as db:
            rows = db.execute("""
                SELECT r.*, m.control_name, m.description, m.severity
                FROM compliance_results r
                JOIN compliance_mappings m ON r.control_id=m.control_id AND r.framework_id=m.framework_id
                WHERE r.user_id=%s AND r.framework_id=%s
                ORDER BY m.control_id
            """, (user_id, framework_id)).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_dashboard(user_id):
        with get_db() as db:
            frameworks = db.execute(
                "SELECT * FROM compliance_frameworks ORDER BY name"
            ).fetchall()
            dashboard = []
            for fw in frameworks:
                fw_id = fw["id"]
                counts = db.execute("""
                    SELECT status, COUNT(*) as cnt FROM compliance_results
                    WHERE user_id=%s AND framework_id=%s
                    GROUP BY status
                """, (user_id, fw_id)).fetchall()
                status_counts = {r["status"]: r["cnt"] for r in counts}
                total = sum(status_counts.values())
                passed = status_counts.get("pass", 0)
                score = round((passed / total) * 100, 1) if total > 0 else 0.0
                dashboard.append({
                    "framework_id": fw_id,
                    "name": fw["name"],
                    "display_name": fw["display_name"],
                    "total_controls": total,
                    "passed": passed,
                    "failed": status_counts.get("fail", 0),
                    "partial": status_counts.get("partial", 0),
                    "not_applicable": status_counts.get("not_applicable", 0),
                    "score": score,
                })
            return dashboard

    @staticmethod
    def export_evidence(user_id, framework_id):
        framework = ComplianceStore.get_framework(framework_id)
        if not framework:
            return None
        results = ComplianceStore.get_results(user_id, framework_id)
        with get_db() as db:
            # Get bucket details for any failures
            failed_controls = [r for r in results if r.get("status") == "fail"]
            bucket_details = []
            if failed_controls:
                rows = db.execute("""
                    SELECT b.id, b.name, b.url, b.status, b.risk_level, b.risk_score,
                           p.name as provider_name
                    FROM buckets b JOIN providers p ON b.provider_id=p.id
                    ORDER BY b.risk_score DESC NULLS LAST
                """).fetchall()
                bucket_details = [dict(r) for r in rows]
        return {
            "framework": framework,
            "results": results,
            "failed_controls": len(failed_controls),
            "total_controls": len(results),
            "bucket_details": bucket_details,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — REMEDIATIONS
# ═══════════════════════════════════════════════════════════════════

class RemediationStore:
    @staticmethod
    def create(bucket_id, user_id, title, priority='medium', alert_id=None,
               assigned_to=None, org_id=None, description=None, due_date=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO remediations
                    (bucket_id, alert_id, user_id, assigned_to, org_id, status, priority,
                     title, description, due_date, notes, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'open', %s, %s, %s, %s, '[]', %s, %s)
            """, (bucket_id, alert_id, user_id, assigned_to, org_id, priority,
                  title, description, due_date, now, now))
            row = db.execute("SELECT * FROM remediations WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get(remediation_id, user_id):
        with get_db() as db:
            row = db.execute("""
                SELECT r.*, b.name as bucket_name, b.url as bucket_url,
                       u.username as assigned_username
                FROM remediations r
                LEFT JOIN buckets b ON r.bucket_id=b.id
                LEFT JOIN users u ON r.assigned_to=u.id
                WHERE r.id=%s AND (r.user_id=%s OR r.assigned_to=%s)
            """, (remediation_id, user_id, user_id)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_by_user(user_id, status=None, assigned_to=None, page=1, per_page=50):
        with get_db() as db:
            q = """
                SELECT r.*, b.name as bucket_name
                FROM remediations r
                LEFT JOIN buckets b ON r.bucket_id=b.id
                WHERE (r.user_id=%s OR r.assigned_to=%s)
            """
            params = [user_id, user_id]
            if status:
                q += " AND r.status=%s"
                params.append(status)
            if assigned_to:
                q += " AND r.assigned_to=%s"
                params.append(assigned_to)
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += """
                ORDER BY
                    CASE r.priority
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                    END,
                    r.created_at DESC
                LIMIT %s OFFSET %s
            """
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    @staticmethod
    def update_status(remediation_id, user_id, status):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            if status == 'closed':
                db.execute(
                    "UPDATE remediations SET status=%s, completed_at=%s, updated_at=%s WHERE id=%s AND (user_id=%s OR assigned_to=%s)",
                    (status, now, now, remediation_id, user_id, user_id),
                )
            else:
                db.execute(
                    "UPDATE remediations SET status=%s, updated_at=%s WHERE id=%s AND (user_id=%s OR assigned_to=%s)",
                    (status, now, remediation_id, user_id, user_id),
                )
            return db.rowcount > 0

    @staticmethod
    def assign(remediation_id, user_id, assigned_to):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute(
                "UPDATE remediations SET assigned_to=%s, updated_at=%s WHERE id=%s AND user_id=%s",
                (assigned_to, now, remediation_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def add_note(remediation_id, user_id, note):
        with get_db() as db:
            row = db.execute(
                "SELECT notes FROM remediations WHERE id=%s AND (user_id=%s OR assigned_to=%s)",
                (remediation_id, user_id, user_id),
            ).fetchone()
            if not row:
                return False
            now = datetime.now(timezone.utc).isoformat()
            notes = json.loads(row["notes"]) if row["notes"] else []
            notes.append({"user_id": user_id, "text": note, "created_at": now})
            db.execute(
                "UPDATE remediations SET notes=%s, updated_at=%s WHERE id=%s",
                (json.dumps(notes), now, remediation_id),
            )
            return True

    @staticmethod
    def get_dashboard(user_id, org_id=None):
        with get_db() as db:
            base_where = "WHERE (user_id=%s OR assigned_to=%s)"
            params = [user_id, user_id]
            if org_id:
                base_where += " AND org_id=%s"
                params.append(org_id)

            # Count by status
            status_rows = db.execute(
                f"SELECT status, COUNT(*) as cnt FROM remediations {base_where} GROUP BY status",
                tuple(params),
            ).fetchall()
            status_counts = {r["status"]: r["cnt"] for r in status_rows}

            # Count overdue
            now = datetime.now(timezone.utc).isoformat()
            overdue_params = list(params) + [now]
            overdue = db.execute(
                f"SELECT COUNT(*) FROM remediations {base_where} AND due_date < %s AND status NOT IN ('closed','verified')",
                tuple(overdue_params),
            ).fetchone()[0]

            # Count by priority
            priority_rows = db.execute(
                f"SELECT priority, COUNT(*) as cnt FROM remediations {base_where} GROUP BY priority",
                tuple(params),
            ).fetchall()
            priority_counts = {r["priority"]: r["cnt"] for r in priority_rows}

            total = sum(status_counts.values())
            return {
                "total": total,
                "by_status": status_counts,
                "by_priority": priority_counts,
                "overdue": overdue,
                "open": status_counts.get("open", 0),
                "in_progress": status_counts.get("in_progress", 0),
                "verified": status_counts.get("verified", 0),
                "closed": status_counts.get("closed", 0),
            }

    @staticmethod
    def get_overdue(user_id):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            rows = db.execute("""
                SELECT r.*, b.name as bucket_name
                FROM remediations r
                LEFT JOIN buckets b ON r.bucket_id=b.id
                WHERE (r.user_id=%s OR r.assigned_to=%s)
                    AND r.due_date < %s
                    AND r.status NOT IN ('closed','verified')
                ORDER BY r.due_date ASC
            """, (user_id, user_id, now)).fetchall()
            return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════════
# COMPLIANCE SEED DATA
# ═══════════════════════════════════════════════════════════════════

COMPLIANCE_SEED = [
    {
        "name": "soc2", "display_name": "SOC 2 Type II", "version": "2024",
        "description": "Service Organization Control 2 — Trust Services Criteria",
        "controls": [
            {"id": "CC6.1", "name": "Logical Access Controls", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "critical"},
            {"id": "CC6.3", "name": "Access Restriction", "check_type": "sensitive_files", "config": {"patterns": [".env", "credentials", ".key", "id_rsa"]}, "severity": "critical"},
            {"id": "CC6.6", "name": "System Boundary Protection", "check_type": "risk_level", "config": {"max_risk_level": "medium"}, "severity": "high"},
            {"id": "CC6.7", "name": "Encryption of Data", "check_type": "encryption", "config": {}, "severity": "high"},
            {"id": "CC7.1", "name": "Detection of Changes", "check_type": "file_classification", "config": {"target_classification": "sensitive"}, "severity": "high"},
            {"id": "CC7.2", "name": "Monitoring for Anomalies", "check_type": "bucket_status", "config": {"max_open_pct": 5}, "severity": "medium"},
            {"id": "CC8.1", "name": "Change Management", "check_type": "risk_level", "config": {"max_risk_level": "high"}, "severity": "medium"},
            {"id": "A1.2", "name": "Data Recovery", "check_type": "bucket_status", "config": {"max_open_pct": 10}, "severity": "medium"},
            {"id": "C1.1", "name": "Confidentiality Commitments", "check_type": "sensitive_files", "config": {"patterns": ["private_key", "secret", "password", "token"]}, "severity": "critical"},
            {"id": "PI1.1", "name": "Privacy Notice", "check_type": "file_classification", "config": {"target_classification": "pii"}, "severity": "high"},
        ],
    },
    {
        "name": "hipaa", "display_name": "HIPAA Security Rule", "version": "2024",
        "description": "Health Insurance Portability and Accountability Act — Security Standards",
        "controls": [
            {"id": "164.312(a)(1)", "name": "Access Control", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "critical"},
            {"id": "164.312(a)(2)(iv)", "name": "Encryption and Decryption", "check_type": "encryption", "config": {}, "severity": "critical"},
            {"id": "164.312(c)(1)", "name": "Integrity Controls", "check_type": "risk_level", "config": {"max_risk_level": "low"}, "severity": "critical"},
            {"id": "164.312(d)", "name": "Authentication", "check_type": "sensitive_files", "config": {"patterns": ["credentials", "password", ".key"]}, "severity": "critical"},
            {"id": "164.312(e)(1)", "name": "Transmission Security", "check_type": "encryption", "config": {}, "severity": "high"},
            {"id": "164.308(a)(1)", "name": "Risk Analysis", "check_type": "risk_level", "config": {"max_risk_level": "medium"}, "severity": "high"},
            {"id": "164.308(a)(3)", "name": "Workforce Security", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "high"},
            {"id": "164.308(a)(4)", "name": "Information Access", "check_type": "sensitive_files", "config": {"patterns": [".env", "config", "database"]}, "severity": "high"},
            {"id": "164.310(d)(1)", "name": "Device and Media Controls", "check_type": "file_classification", "config": {"target_classification": "medical"}, "severity": "critical"},
            {"id": "164.316(b)(1)", "name": "Documentation", "check_type": "bucket_status", "config": {"max_open_pct": 5}, "severity": "medium"},
        ],
    },
    {
        "name": "pci_dss", "display_name": "PCI DSS v4.0", "version": "4.0",
        "description": "Payment Card Industry Data Security Standard",
        "controls": [
            {"id": "1.3.1", "name": "Cardholder Data Restriction", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "critical"},
            {"id": "3.4", "name": "Render PAN Unreadable", "check_type": "file_classification", "config": {"target_classification": "financial"}, "severity": "critical"},
            {"id": "3.5.1", "name": "Encryption Key Protection", "check_type": "sensitive_files", "config": {"patterns": [".key", "private_key", "master.key", ".pem"]}, "severity": "critical"},
            {"id": "4.1", "name": "Strong Cryptography", "check_type": "encryption", "config": {}, "severity": "critical"},
            {"id": "6.5.3", "name": "Insecure Storage", "check_type": "sensitive_files", "config": {"patterns": [".env", "credentials", "password", "secret"]}, "severity": "high"},
            {"id": "7.1", "name": "Least Privilege Access", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "high"},
            {"id": "8.2.1", "name": "Strong Authentication", "check_type": "sensitive_files", "config": {"patterns": ["token", "api_key", "auth"]}, "severity": "high"},
            {"id": "10.2", "name": "Audit Trail", "check_type": "risk_level", "config": {"max_risk_level": "medium"}, "severity": "medium"},
            {"id": "11.5", "name": "File Integrity Monitoring", "check_type": "file_classification", "config": {"target_classification": "sensitive"}, "severity": "high"},
            {"id": "12.3.1", "name": "Risk Assessment", "check_type": "risk_level", "config": {"max_risk_level": "high"}, "severity": "medium"},
        ],
    },
    {
        "name": "gdpr", "display_name": "GDPR", "version": "2018",
        "description": "General Data Protection Regulation — EU Data Privacy",
        "controls": [
            {"id": "Art.5(1)(f)", "name": "Integrity and Confidentiality", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "critical"},
            {"id": "Art.25", "name": "Data Protection by Design", "check_type": "risk_level", "config": {"max_risk_level": "low"}, "severity": "high"},
            {"id": "Art.32(1)(a)", "name": "Encryption of Personal Data", "check_type": "encryption", "config": {}, "severity": "critical"},
            {"id": "Art.32(1)(b)", "name": "Confidentiality of Systems", "check_type": "sensitive_files", "config": {"patterns": [".env", "credentials", "password"]}, "severity": "high"},
            {"id": "Art.33", "name": "Breach Notification Readiness", "check_type": "file_classification", "config": {"target_classification": "pii"}, "severity": "critical"},
            {"id": "Art.35", "name": "Data Protection Impact", "check_type": "risk_level", "config": {"max_risk_level": "medium"}, "severity": "high"},
            {"id": "Art.5(1)(e)", "name": "Storage Limitation", "check_type": "bucket_status", "config": {"max_open_pct": 5}, "severity": "medium"},
            {"id": "Art.5(1)(d)", "name": "Data Accuracy", "check_type": "file_classification", "config": {"target_classification": "sensitive"}, "severity": "medium"},
            {"id": "Art.24", "name": "Controller Responsibility", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "high"},
            {"id": "Art.28", "name": "Processor Requirements", "check_type": "sensitive_files", "config": {"patterns": ["config", "database", "backup"]}, "severity": "medium"},
        ],
    },
    {
        "name": "iso27001", "display_name": "ISO 27001:2022", "version": "2022",
        "description": "Information Security Management Systems — Requirements",
        "controls": [
            {"id": "A.8.1", "name": "Asset Inventory", "check_type": "bucket_status", "config": {"max_open_pct": 10}, "severity": "medium"},
            {"id": "A.8.3", "name": "Access Restriction", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "critical"},
            {"id": "A.8.10", "name": "Information Deletion", "check_type": "sensitive_files", "config": {"patterns": [".env", "credentials", "secret"]}, "severity": "high"},
            {"id": "A.8.24", "name": "Use of Cryptography", "check_type": "encryption", "config": {}, "severity": "high"},
            {"id": "A.5.15", "name": "Access Control Policy", "check_type": "bucket_status", "config": {"max_open_pct": 0}, "severity": "high"},
            {"id": "A.8.9", "name": "Configuration Management", "check_type": "sensitive_files", "config": {"patterns": ["config", "terraform", ".yaml", ".yml"]}, "severity": "medium"},
            {"id": "A.8.12", "name": "Data Classification", "check_type": "file_classification", "config": {"target_classification": "sensitive"}, "severity": "high"},
            {"id": "A.6.1", "name": "Personnel Screening", "check_type": "risk_level", "config": {"max_risk_level": "medium"}, "severity": "medium"},
            {"id": "A.5.23", "name": "Cloud Services Security", "check_type": "risk_level", "config": {"max_risk_level": "low"}, "severity": "high"},
            {"id": "A.8.16", "name": "Monitoring Activities", "check_type": "bucket_status", "config": {"max_open_pct": 5}, "severity": "medium"},
        ],
    },
]


def seed_compliance_frameworks():
    """Seed compliance frameworks and control mappings into the database."""
    with get_db() as db:
        for fw in COMPLIANCE_SEED:
            existing = db.execute(
                "SELECT id FROM compliance_frameworks WHERE name=%s", (fw["name"],)
            ).fetchone()
            if existing:
                fw_id = existing["id"]
            else:
                db.execute(
                    "INSERT INTO compliance_frameworks (name, display_name, version, description, controls) VALUES (%s,%s,%s,%s,%s)",
                    (fw["name"], fw["display_name"], fw["version"], fw["description"], json.dumps(fw["controls"])),
                )
                fw_id = db.lastrowid
            for ctrl in fw["controls"]:
                existing_ctrl = db.execute(
                    "SELECT id FROM compliance_mappings WHERE framework_id=%s AND control_id=%s",
                    (fw_id, ctrl["id"]),
                ).fetchone()
                if not existing_ctrl:
                    db.execute(
                        "INSERT INTO compliance_mappings (framework_id, control_id, control_name, check_type, check_config, severity) VALUES (%s,%s,%s,%s,%s,%s)",
                        (fw_id, ctrl["id"], ctrl["name"], ctrl["check_type"], json.dumps(ctrl.get("config", {})), ctrl.get("severity", "medium")),
                    )
    logger.info("Compliance frameworks seeded")


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — TAGS
# ═══════════════════════════════════════════════════════════════════

class TagStore:
    @staticmethod
    def create(user_id, name, color='#6b7280'):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute(
                "INSERT INTO tags (user_id, name, color, created_at) VALUES (%s, %s, %s, %s)",
                (user_id, name, color, now),
            )
            row = db.execute("SELECT * FROM tags WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM tags WHERE user_id=%s ORDER BY name",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def update(tag_id, user_id, **kwargs):
        allowed = {"name", "color"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        params.extend([tag_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE tags SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(tag_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM tags WHERE id=%s AND user_id=%s",
                (tag_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def tag_bucket(user_id, bucket_id, tag_id):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            if settings.is_postgres:
                db.execute(
                    "INSERT INTO bucket_tags (bucket_id, tag_id, user_id, created_at) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                    (bucket_id, tag_id, user_id, now),
                )
            else:
                db.execute(
                    "INSERT OR IGNORE INTO bucket_tags (bucket_id, tag_id, user_id, created_at) VALUES (%s, %s, %s, %s)",
                    (bucket_id, tag_id, user_id, now),
                )

    @staticmethod
    def untag_bucket(user_id, bucket_id, tag_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM bucket_tags WHERE bucket_id=%s AND tag_id=%s AND user_id=%s",
                (bucket_id, tag_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def get_bucket_tags(bucket_id, user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT t.* FROM tags t JOIN bucket_tags bt ON bt.tag_id=t.id WHERE bt.bucket_id=%s AND bt.user_id=%s ORDER BY t.name",
                (bucket_id, user_id),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_buckets_by_tag(tag_id, user_id, page=1, per_page=50):
        with get_db() as db:
            q = """SELECT b.*, p.name as provider_name, p.display_name as provider_display
                   FROM buckets b
                   JOIN bucket_tags bt ON bt.bucket_id=b.id
                   JOIN providers p ON b.provider_id=p.id
                   WHERE bt.tag_id=%s AND bt.user_id=%s"""
            params = [tag_id, user_id]
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY b.last_scanned DESC NULLS LAST LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — BOOKMARKS
# ═══════════════════════════════════════════════════════════════════

class BookmarkStore:
    @staticmethod
    def toggle(user_id, bucket_id=None, file_id=None, note=None):
        with get_db() as db:
            # Check if bookmark exists
            if bucket_id:
                existing = db.execute(
                    "SELECT id FROM bookmarks WHERE user_id=%s AND bucket_id=%s",
                    (user_id, bucket_id),
                ).fetchone()
            elif file_id:
                existing = db.execute(
                    "SELECT id FROM bookmarks WHERE user_id=%s AND file_id=%s",
                    (user_id, file_id),
                ).fetchone()
            else:
                return {"error": "bucket_id or file_id required"}

            if existing:
                db.execute("DELETE FROM bookmarks WHERE id=%s", (existing["id"],))
                return {"bookmarked": False}
            else:
                now = datetime.now(timezone.utc).isoformat()
                db.execute(
                    "INSERT INTO bookmarks (user_id, bucket_id, file_id, note, created_at) VALUES (%s, %s, %s, %s, %s)",
                    (user_id, bucket_id, file_id, note, now),
                )
                row = db.execute("SELECT * FROM bookmarks WHERE id=%s", (db.lastrowid,)).fetchone()
                result = dict(row) if row else {}
                result["bookmarked"] = True
                return result

    @staticmethod
    def list_by_user(user_id, bm_type='all', page=1, per_page=50):
        with get_db() as db:
            q = "SELECT * FROM bookmarks WHERE user_id=%s"
            params = [user_id]
            if bm_type == 'bucket':
                q += " AND bucket_id IS NOT NULL"
            elif bm_type == 'file':
                q += " AND file_id IS NOT NULL"
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def is_bookmarked(user_id, bucket_id=None, file_id=None):
        with get_db() as db:
            if bucket_id:
                row = db.execute(
                    "SELECT id FROM bookmarks WHERE user_id=%s AND bucket_id=%s",
                    (user_id, bucket_id),
                ).fetchone()
            elif file_id:
                row = db.execute(
                    "SELECT id FROM bookmarks WHERE user_id=%s AND file_id=%s",
                    (user_id, file_id),
                ).fetchone()
            else:
                return False
            return row is not None

    @staticmethod
    def get_bucket_bookmark_ids(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT bucket_id FROM bookmarks WHERE user_id=%s AND bucket_id IS NOT NULL",
                (user_id,),
            ).fetchall()
            return [r["bucket_id"] for r in rows]


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — SCAN SCHEDULES
# ═══════════════════════════════════════════════════════════════════

class ScanScheduleStore:
    @staticmethod
    def _compute_next_run(frequency):
        """Compute the next run time based on frequency."""
        now = datetime.now(timezone.utc)
        if frequency == 'hourly':
            return (now + timedelta(hours=1)).isoformat()
        elif frequency == 'daily':
            return (now + timedelta(hours=24)).isoformat()
        elif frequency == 'weekly':
            return (now + timedelta(days=7)).isoformat()
        elif frequency == 'monthly':
            return (now + timedelta(days=30)).isoformat()
        return (now + timedelta(hours=24)).isoformat()

    @staticmethod
    def create(user_id, name, keywords, companies=None, providers=None, frequency='daily', config=None):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_run = ScanScheduleStore._compute_next_run(frequency)
            config_str = json.dumps(config) if isinstance(config, dict) else (config or '{}')
            db.execute("""
                INSERT INTO scan_schedules (user_id, name, keywords, companies, providers,
                    frequency, next_run_at, config, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, name, json.dumps(keywords), json.dumps(companies or []),
                  json.dumps(providers or []), frequency, next_run, config_str, now, now))
            row = db.execute("SELECT * FROM scan_schedules WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id):
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM scan_schedules WHERE user_id=%s ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get(schedule_id, user_id):
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM scan_schedules WHERE id=%s AND user_id=%s",
                (schedule_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(schedule_id, user_id, **kwargs):
        allowed = {"name", "keywords", "companies", "providers", "frequency", "is_active", "config"}
        updates, params = [], []
        new_frequency = kwargs.get("frequency")
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                if k in ("keywords", "companies", "providers") and isinstance(v, list):
                    v = json.dumps(v)
                elif k == "config" and isinstance(v, dict):
                    v = json.dumps(v)
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at=%s")
        params.append(now)
        if new_frequency:
            next_run = ScanScheduleStore._compute_next_run(new_frequency)
            updates.append("next_run_at=%s")
            params.append(next_run)
        params.extend([schedule_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE scan_schedules SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(schedule_id, user_id):
        with get_db() as db:
            db.execute(
                "DELETE FROM scan_schedules WHERE id=%s AND user_id=%s",
                (schedule_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def list_due():
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            rows = db.execute(
                "SELECT * FROM scan_schedules WHERE is_active=%s AND (next_run_at IS NULL OR next_run_at <= %s)",
                (True, now),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def mark_run(schedule_id, job_id, frequency):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            next_run = ScanScheduleStore._compute_next_run(frequency)
            db.execute(
                "UPDATE scan_schedules SET last_run_at=%s, last_job_id=%s, next_run_at=%s, updated_at=%s WHERE id=%s",
                (now, job_id, next_run, now, schedule_id),
            )


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — AUDIT LOG
# ═══════════════════════════════════════════════════════════════════

class AuditLogStore:
    @staticmethod
    def log(user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
        try:
            with get_db() as db:
                now = datetime.now(timezone.utc).isoformat()
                details_str = json.dumps(details) if isinstance(details, dict) else details
                db.execute("""
                    INSERT INTO audit_log (user_id, action, entity_type, entity_id, details, ip_address, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (user_id, action, entity_type, entity_id, details_str, ip_address, now))
        except Exception as e:
            logger.debug(f"Failed to write audit log: {e}")

    @staticmethod
    def list_by_user(user_id, action=None, entity_type=None, page=1, per_page=50):
        with get_db() as db:
            q = "SELECT * FROM audit_log WHERE user_id=%s"
            params = [user_id]
            if action:
                q += " AND action=%s"
                params.append(action)
            if entity_type:
                q += " AND entity_type=%s"
                params.append(entity_type)
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def list_by_entity(entity_type, entity_id, page=1, per_page=50):
        with get_db() as db:
            q = "SELECT * FROM audit_log WHERE entity_type=%s AND entity_id=%s"
            params = [entity_type, entity_id]
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — SCAN SNAPSHOTS & DRIFT DETECTION
# ═══════════════════════════════════════════════════════════════════

class ScanSnapshotStore:
    @staticmethod
    def capture(scan_job_id: int, bucket_id: int, status: str,
                file_count: int, total_size_bytes: int, file_hashes: list = None) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            hashes_str = json.dumps(file_hashes or [])
            if settings.is_postgres:
                db.execute("""
                    INSERT INTO scan_snapshots (scan_job_id, bucket_id, status, file_count, total_size_bytes, file_hashes, captured_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (scan_job_id, bucket_id) DO UPDATE SET
                        status=excluded.status, file_count=excluded.file_count,
                        total_size_bytes=excluded.total_size_bytes, file_hashes=excluded.file_hashes,
                        captured_at=excluded.captured_at
                """, (scan_job_id, bucket_id, status, file_count, total_size_bytes, hashes_str, now))
            else:
                db.execute("""
                    INSERT OR REPLACE INTO scan_snapshots (scan_job_id, bucket_id, status, file_count, total_size_bytes, file_hashes, captured_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (scan_job_id, bucket_id, status, file_count, total_size_bytes, hashes_str, now))
            row = db.execute(
                "SELECT * FROM scan_snapshots WHERE scan_job_id=%s AND bucket_id=%s",
                (scan_job_id, bucket_id),
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get_latest_for_bucket(bucket_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM scan_snapshots WHERE bucket_id=%s ORDER BY captured_at DESC LIMIT 1",
                (bucket_id,),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_previous_for_bucket(bucket_id: int, before_snapshot_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM scan_snapshots WHERE bucket_id=%s AND id < %s ORDER BY captured_at DESC LIMIT 1",
                (bucket_id, before_snapshot_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def list_for_bucket(bucket_id: int, limit: int = 20) -> list[dict]:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM scan_snapshots WHERE bucket_id=%s ORDER BY captured_at DESC LIMIT %s",
                (bucket_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def list_for_job(scan_job_id: int) -> list[dict]:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM scan_snapshots WHERE scan_job_id=%s ORDER BY bucket_id",
                (scan_job_id,),
            ).fetchall()
            return [dict(r) for r in rows]


class ScanDiffStore:
    @staticmethod
    def create(bucket_id: int, old_snapshot_id: int, new_snapshot_id: int,
               diff_type: str, summary: str, details: dict = None, severity: str = "info") -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO scan_diffs (bucket_id, old_snapshot_id, new_snapshot_id, diff_type,
                    summary, details, severity, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (bucket_id, old_snapshot_id, new_snapshot_id, diff_type,
                  summary, json.dumps(details or {}), severity, now))
            row = db.execute("SELECT * FROM scan_diffs WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_for_bucket(bucket_id: int, page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            q = "SELECT * FROM scan_diffs WHERE bucket_id=%s"
            params = [bucket_id]
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page}

    @staticmethod
    def list_recent(user_id: int = None, severity: str = None, unreviewed_only: bool = False,
                    page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            q = """SELECT d.*, b.name as bucket_name, b.url as bucket_url,
                          p.name as provider_name, p.display_name as provider_display
                   FROM scan_diffs d
                   JOIN buckets b ON d.bucket_id=b.id
                   JOIN providers p ON b.provider_id=p.id
                   WHERE 1=1"""
            params = []
            if severity:
                q += " AND d.severity=%s"
                params.append(severity)
            if unreviewed_only:
                q += f" AND d.is_reviewed={_bool_sql(False)}"
            total = db.execute(f"SELECT COUNT(*) FROM ({q})", tuple(params)).fetchone()[0]
            q += " ORDER BY d.created_at DESC LIMIT %s OFFSET %s"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, tuple(params)).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page}

    @staticmethod
    def mark_reviewed(diff_id: int):
        with get_db() as db:
            db.execute(f"UPDATE scan_diffs SET is_reviewed={_bool_sql(True)} WHERE id=%s", (diff_id,))
            return db.rowcount > 0

    @staticmethod
    def get_summary() -> dict:
        with get_db() as db:
            total = db.execute("SELECT COUNT(*) FROM scan_diffs").fetchone()[0]
            unreviewed = db.execute(
                f"SELECT COUNT(*) FROM scan_diffs WHERE is_reviewed={_bool_sql(False)}"
            ).fetchone()[0]
            by_severity = db.execute("""
                SELECT severity, COUNT(*) as cnt FROM scan_diffs
                GROUP BY severity ORDER BY cnt DESC
            """).fetchall()
            by_type = db.execute("""
                SELECT diff_type, COUNT(*) as cnt FROM scan_diffs
                GROUP BY diff_type ORDER BY cnt DESC
            """).fetchall()
            return {
                "total": total,
                "unreviewed": unreviewed,
                "by_severity": {r["severity"]: r["cnt"] for r in by_severity},
                "by_type": {r["diff_type"]: r["cnt"] for r in by_type},
            }

    @staticmethod
    def compute_diffs(scan_job_id: int) -> list[dict]:
        """Compare snapshots from this scan against previous snapshots for each bucket."""
        diffs = []
        snapshots = ScanSnapshotStore.list_for_job(scan_job_id)
        for snap in snapshots:
            bucket_id = snap["bucket_id"]
            prev = ScanSnapshotStore.get_previous_for_bucket(bucket_id, snap["id"])

            if not prev:
                # New bucket first seen
                d = ScanDiffStore.create(
                    bucket_id=bucket_id,
                    old_snapshot_id=None,
                    new_snapshot_id=snap["id"],
                    diff_type="new_bucket",
                    summary=f"New bucket discovered with {snap['file_count']} files",
                    details={"file_count": snap["file_count"], "status": snap["status"]},
                    severity="high" if snap["status"] == "open" else "info",
                )
                diffs.append(d)
                continue

            # Status change
            if prev["status"] != snap["status"]:
                sev = "critical" if snap["status"] == "open" and prev["status"] == "closed" else \
                      "high" if snap["status"] == "open" else "info"
                d = ScanDiffStore.create(
                    bucket_id=bucket_id,
                    old_snapshot_id=prev["id"],
                    new_snapshot_id=snap["id"],
                    diff_type="status_change",
                    summary=f"Status changed: {prev['status']} → {snap['status']}",
                    details={"old_status": prev["status"], "new_status": snap["status"]},
                    severity=sev,
                )
                diffs.append(d)

            # Files added
            file_diff = snap["file_count"] - prev["file_count"]
            if file_diff > 0:
                sev = "high" if file_diff > 100 else "medium" if file_diff > 10 else "low"
                d = ScanDiffStore.create(
                    bucket_id=bucket_id,
                    old_snapshot_id=prev["id"],
                    new_snapshot_id=snap["id"],
                    diff_type="files_added",
                    summary=f"{file_diff} new files detected (was {prev['file_count']}, now {snap['file_count']})",
                    details={"old_count": prev["file_count"], "new_count": snap["file_count"], "diff": file_diff},
                    severity=sev,
                )
                diffs.append(d)

            # Files removed
            if file_diff < 0:
                d = ScanDiffStore.create(
                    bucket_id=bucket_id,
                    old_snapshot_id=prev["id"],
                    new_snapshot_id=snap["id"],
                    diff_type="files_removed",
                    summary=f"{abs(file_diff)} files removed (was {prev['file_count']}, now {snap['file_count']})",
                    details={"old_count": prev["file_count"], "new_count": snap["file_count"], "diff": file_diff},
                    severity="low",
                )
                diffs.append(d)

            # Significant size change (>20%)
            if prev["total_size_bytes"] > 0:
                size_pct = abs(snap["total_size_bytes"] - prev["total_size_bytes"]) / prev["total_size_bytes"]
                if size_pct > 0.2:
                    d = ScanDiffStore.create(
                        bucket_id=bucket_id,
                        old_snapshot_id=prev["id"],
                        new_snapshot_id=snap["id"],
                        diff_type="size_change",
                        summary=f"Size changed by {size_pct:.0%} ({prev['total_size_bytes']} → {snap['total_size_bytes']} bytes)",
                        details={"old_size": prev["total_size_bytes"], "new_size": snap["total_size_bytes"],
                                 "pct_change": round(size_pct * 100, 1)},
                        severity="medium" if size_pct > 1.0 else "low",
                    )
                    diffs.append(d)

        return diffs


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — CUSTOM ALERT RULES
# ═══════════════════════════════════════════════════════════════════

class AlertRuleStore:
    @staticmethod
    def create(user_id: int, name: str, conditions: list, severity: str = "medium",
               description: str = None, actions: list = None) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("""
                INSERT INTO alert_rules (user_id, name, description, conditions, actions, severity, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, name, description, json.dumps(conditions),
                  json.dumps(actions or ["alert"]), severity, now, now))
            row = db.execute("SELECT * FROM alert_rules WHERE id=%s", (db.lastrowid,)).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def list_by_user(user_id: int) -> list[dict]:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM alert_rules WHERE user_id=%s ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get(rule_id: int, user_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM alert_rules WHERE id=%s AND user_id=%s",
                (rule_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(rule_id: int, user_id: int, **kwargs) -> bool:
        allowed = {"name", "description", "conditions", "actions", "severity", "is_active"}
        updates, params = [], []
        for k, v in kwargs.items():
            if k in allowed and v is not None:
                if k in ("conditions", "actions") and isinstance(v, list):
                    v = json.dumps(v)
                updates.append(f"{k}=%s")
                params.append(v)
        if not updates:
            return False
        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at=%s")
        params.append(now)
        params.extend([rule_id, user_id])
        with get_db() as db:
            db.execute(
                f"UPDATE alert_rules SET {','.join(updates)} WHERE id=%s AND user_id=%s",
                tuple(params),
            )
            return db.rowcount > 0

    @staticmethod
    def delete(rule_id: int, user_id: int) -> bool:
        with get_db() as db:
            db.execute(
                "DELETE FROM alert_rules WHERE id=%s AND user_id=%s",
                (rule_id, user_id),
            )
            return db.rowcount > 0

    @staticmethod
    def increment_match(rule_id: int):
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute(
                "UPDATE alert_rules SET match_count=match_count+1, last_matched_at=%s WHERE id=%s",
                (now, rule_id),
            )

    @staticmethod
    def get_active_for_user(user_id: int) -> list[dict]:
        with get_db() as db:
            rows = db.execute(
                f"SELECT * FROM alert_rules WHERE user_id=%s AND is_active={_bool_sql(True)}",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def evaluate_bucket(user_id: int, bucket: dict, files: list[dict] = None) -> list[dict]:
        """Evaluate all active rules for a user against a bucket/files. Returns triggered alerts."""
        rules = AlertRuleStore.get_active_for_user(user_id)
        triggered = []
        for rule in rules:
            conditions = json.loads(rule["conditions"]) if isinstance(rule["conditions"], str) else rule["conditions"]
            matched = True
            for cond in conditions:
                cond_type = cond.get("type")
                if cond_type == "file_extension":
                    target_ext = cond.get("value", "").lower().lstrip(".")
                    if not files or not any(
                        (f.get("extension", "").lower().lstrip(".") == target_ext) for f in files
                    ):
                        matched = False
                        break
                elif cond_type == "file_size_gt":
                    threshold = int(cond.get("value", 0))
                    if not files or not any(f.get("size_bytes", 0) > threshold for f in files):
                        matched = False
                        break
                elif cond_type == "file_name_contains":
                    pattern = cond.get("value", "").lower()
                    if not files or not any(pattern in f.get("filename", "").lower() for f in files):
                        matched = False
                        break
                elif cond_type == "bucket_name_contains":
                    pattern = cond.get("value", "").lower()
                    if pattern not in bucket.get("name", "").lower():
                        matched = False
                        break
                elif cond_type == "bucket_status":
                    target_status = cond.get("value", "open")
                    if bucket.get("status") != target_status:
                        matched = False
                        break
                elif cond_type == "provider":
                    target_provider = cond.get("value", "")
                    if bucket.get("provider_name", "") != target_provider:
                        matched = False
                        break
                elif cond_type == "file_count_gt":
                    threshold = int(cond.get("value", 0))
                    if bucket.get("file_count", 0) <= threshold:
                        matched = False
                        break
                elif cond_type == "classification":
                    target_class = cond.get("value", "")
                    if not files or not any(f.get("ai_classification") == target_class for f in files):
                        matched = False
                        break

            if matched:
                AlertRuleStore.increment_match(rule["id"])
                triggered.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "actions": json.loads(rule["actions"]) if isinstance(rule["actions"], str) else rule["actions"],
                })
        return triggered


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — CSRF TOKENS
# ═══════════════════════════════════════════════════════════════════

class CsrfTokenStore:
    @staticmethod
    def generate(user_id: int = None, session_id: str = None) -> str:
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        with get_db() as db:
            db.execute(
                "INSERT INTO csrf_tokens (token, user_id, session_id, expires_at) VALUES (%s, %s, %s, %s)",
                (token, user_id, session_id, expires),
            )
        return token

    @staticmethod
    def validate(token: str, user_id: int = None) -> bool:
        if not token:
            return False
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM csrf_tokens WHERE token=%s", (token,)
            ).fetchone()
            if not row:
                return False
            # Check expiry
            expires = datetime.fromisoformat(str(row["expires_at"]))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires < datetime.now(timezone.utc):
                db.execute("DELETE FROM csrf_tokens WHERE id=%s", (row["id"],))
                return False
            # Consume token (single-use)
            db.execute("DELETE FROM csrf_tokens WHERE id=%s", (row["id"],))
            return True

    @staticmethod
    def cleanup_expired():
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute("DELETE FROM csrf_tokens WHERE expires_at < %s", (now,))


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — DASHBOARD STATS
# ═══════════════════════════════════════════════════════════════════

class DashboardStatsStore:
    @staticmethod
    def get_risk_trends(days: int = 30) -> dict:
        """Get risk score trends over time by looking at scan snapshots."""
        with get_db() as db:
            if settings.is_postgres:
                rows = db.execute("""
                    SELECT captured_at::date::text as day,
                           COUNT(DISTINCT bucket_id) as buckets_scanned,
                           AVG(file_count) as avg_files,
                           SUM(file_count) as total_files,
                           COUNT(CASE WHEN status='open' THEN 1 END) as open_count,
                           COUNT(CASE WHEN status='closed' THEN 1 END) as closed_count
                    FROM scan_snapshots
                    WHERE captured_at >= NOW() - INTERVAL '%s days'
                    GROUP BY captured_at::date
                    ORDER BY day
                """ % days).fetchall()
            else:
                cutoff = f"-{days} days"
                rows = db.execute("""
                    SELECT date(captured_at) as day,
                           COUNT(DISTINCT bucket_id) as buckets_scanned,
                           AVG(file_count) as avg_files,
                           SUM(file_count) as total_files,
                           SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open_count,
                           SUM(CASE WHEN status='closed' THEN 1 ELSE 0 END) as closed_count
                    FROM scan_snapshots
                    WHERE captured_at >= datetime('now', %s)
                    GROUP BY date(captured_at)
                    ORDER BY day
                """, (cutoff,)).fetchall()
            return {"risk_trends": [dict(r) for r in rows], "days": days}

    @staticmethod
    def get_remediation_sla(user_id: int) -> dict:
        """Get remediation SLA metrics."""
        with get_db() as db:
            base_where = "WHERE (user_id=%s OR assigned_to=%s)"
            params = [user_id, user_id]

            # Average time to close
            if settings.is_postgres:
                closed_rows = db.execute(f"""
                    SELECT priority,
                           COUNT(*) as count,
                           AVG(CASE WHEN completed_at IS NOT NULL AND created_at IS NOT NULL
                               THEN EXTRACT(EPOCH FROM (completed_at - created_at)) / 86400.0 END) as avg_days_to_close
                    FROM remediations {base_where} AND status='closed' AND completed_at IS NOT NULL
                    GROUP BY priority
                """, tuple(params)).fetchall()
            else:
                closed_rows = db.execute(f"""
                    SELECT priority,
                           COUNT(*) as count,
                           AVG(CASE WHEN completed_at IS NOT NULL AND created_at IS NOT NULL
                               THEN julianday(completed_at) - julianday(created_at) END) as avg_days_to_close
                    FROM remediations {base_where} AND status='closed' AND completed_at IS NOT NULL
                    GROUP BY priority
                """, tuple(params)).fetchall()

            # Overdue count by priority
            now = datetime.now(timezone.utc).isoformat()
            overdue_params = list(params) + [now]
            overdue_rows = db.execute(f"""
                SELECT priority, COUNT(*) as cnt
                FROM remediations {base_where} AND due_date < %s AND status NOT IN ('closed','verified')
                GROUP BY priority
            """, tuple(overdue_params)).fetchall()

            # Open aging
            if settings.is_postgres:
                aging_rows = db.execute(f"""
                    SELECT
                        SUM(CASE WHEN EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 <= 7 THEN 1 ELSE 0 END) as this_week,
                        SUM(CASE WHEN EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 BETWEEN 7 AND 30 THEN 1 ELSE 0 END) as this_month,
                        SUM(CASE WHEN EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400.0 > 30 THEN 1 ELSE 0 END) as older
                    FROM remediations {base_where} AND status NOT IN ('closed','verified')
                """, tuple(params)).fetchone()
            else:
                aging_rows = db.execute(f"""
                    SELECT
                        SUM(CASE WHEN julianday('now') - julianday(created_at) <= 7 THEN 1 ELSE 0 END) as this_week,
                        SUM(CASE WHEN julianday('now') - julianday(created_at) BETWEEN 7 AND 30 THEN 1 ELSE 0 END) as this_month,
                        SUM(CASE WHEN julianday('now') - julianday(created_at) > 30 THEN 1 ELSE 0 END) as older
                    FROM remediations {base_where} AND status NOT IN ('closed','verified')
                """, tuple(params)).fetchone()

            return {
                "time_to_close": {r["priority"]: {"count": r["count"], "avg_days": round(r["avg_days_to_close"] or 0, 1)} for r in closed_rows},
                "overdue_by_priority": {r["priority"]: r["cnt"] for r in overdue_rows},
                "open_aging": dict(aging_rows) if aging_rows else {"this_week": 0, "this_month": 0, "older": 0},
            }

    @staticmethod
    def get_executive_summary(user_id: int = None) -> dict:
        """High-level executive dashboard stats."""
        with get_db() as db:
            # Overall stats
            total_buckets = db.execute("SELECT COUNT(*) FROM buckets").fetchone()[0]
            open_buckets = db.execute("SELECT COUNT(*) FROM buckets WHERE status='open'").fetchone()[0]
            total_files = db.execute("SELECT COUNT(*) FROM files").fetchone()[0]
            total_size = db.execute("SELECT COALESCE(SUM(size_bytes),0) FROM files").fetchone()[0]

            # Risk distribution
            risk_dist = db.execute("""
                SELECT risk_level, COUNT(*) as cnt
                FROM buckets WHERE risk_level IS NOT NULL
                GROUP BY risk_level
            """).fetchall()

            # Sensitive file counts
            sensitive = db.execute("""
                SELECT ai_classification, COUNT(*) as cnt
                FROM files WHERE ai_classification IN ('credentials','pii','financial','medical')
                GROUP BY ai_classification
            """).fetchall()

            # Recent activity
            if settings.is_postgres:
                recent_scans = db.execute("""
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
                           SUM(buckets_found) as buckets_found,
                           SUM(files_indexed) as files_indexed
                    FROM scan_jobs
                    WHERE created_at >= NOW() - INTERVAL '7 days'
                """).fetchone()
            else:
                recent_scans = db.execute("""
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
                           SUM(buckets_found) as buckets_found,
                           SUM(files_indexed) as files_indexed
                    FROM scan_jobs
                    WHERE created_at >= datetime('now', '-7 days')
                """).fetchone()

            # Alert severity breakdown (unresolved)
            alert_sev = db.execute(f"""
                SELECT severity, COUNT(*) as cnt
                FROM alerts WHERE is_resolved={_bool_sql(False)}
                GROUP BY severity
            """).fetchall()

            # Top exposed organizations (by bucket name patterns)
            top_exposed = db.execute("""
                SELECT name, file_count, status, risk_level, risk_score
                FROM buckets WHERE status='open'
                ORDER BY file_count DESC LIMIT 10
            """).fetchall()

            # Drift summary
            drift_summary = ScanDiffStore.get_summary()

            return {
                "total_buckets": total_buckets,
                "open_buckets": open_buckets,
                "exposure_rate": round((open_buckets / total_buckets * 100), 1) if total_buckets > 0 else 0,
                "total_files": total_files,
                "total_size_bytes": total_size,
                "risk_distribution": {r["risk_level"]: r["cnt"] for r in risk_dist},
                "sensitive_files": {r["ai_classification"]: r["cnt"] for r in sensitive},
                "recent_scans": dict(recent_scans) if recent_scans else {},
                "unresolved_alerts": {r["severity"]: r["cnt"] for r in alert_sev},
                "top_exposed_buckets": [dict(r) for r in top_exposed],
                "drift_summary": drift_summary,
            }
