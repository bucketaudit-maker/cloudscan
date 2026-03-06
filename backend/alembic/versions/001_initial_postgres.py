"""Initial PostgreSQL schema with full-text search (tsvector).

Revision ID: 001
Revises:
Create Date: 2025-03-05

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS providers (
            id          INTEGER PRIMARY KEY,
            name        TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            bucket_term TEXT NOT NULL,
            endpoint_pattern TEXT,
            created_at  TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            email           TEXT UNIQUE NOT NULL,
            username        TEXT UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            tier            TEXT DEFAULT 'free' CHECK(tier IN ('free','premium','enterprise')),
            api_key         TEXT UNIQUE,
            is_active       BOOLEAN DEFAULT true,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
            last_login      TIMESTAMPTZ,
            queries_today   INTEGER DEFAULT 0,
            queries_reset_at TIMESTAMPTZ
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS buckets (
            id              SERIAL PRIMARY KEY,
            provider_id     INTEGER NOT NULL REFERENCES providers(id),
            name            TEXT NOT NULL,
            region          TEXT DEFAULT '',
            url             TEXT NOT NULL,
            status          TEXT DEFAULT 'unknown' CHECK(status IN ('open','closed','partial','error','unknown')),
            file_count      INTEGER DEFAULT 0,
            total_size_bytes BIGINT DEFAULT 0,
            first_seen      TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
            last_scanned    TIMESTAMPTZ,
            last_status_check TIMESTAMPTZ,
            scan_time_ms    INTEGER DEFAULT 0,
            metadata        TEXT,
            UNIQUE(provider_id, name, region)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id              SERIAL PRIMARY KEY,
            bucket_id       INTEGER NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
            filepath        TEXT NOT NULL,
            filename        TEXT NOT NULL,
            extension       TEXT DEFAULT '',
            size_bytes      BIGINT DEFAULT 0,
            last_modified   TIMESTAMPTZ,
            etag            TEXT,
            content_type    TEXT DEFAULT '',
            url             TEXT NOT NULL,
            indexed_at      TIMESTAMPTZ NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
            metadata        TEXT,
            search_vector   tsvector GENERATED ALWAYS AS (
                to_tsvector('english', coalesce(filepath,'') || ' ' || coalesce(filename,'') || ' ' || coalesce(extension,'') || ' ' || coalesce(content_type,''))
            ) STORED,
            UNIQUE(bucket_id, filepath)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_files_search ON files USING GIN (search_vector)")
    op.execute("""
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id              SERIAL PRIMARY KEY,
            job_type        TEXT NOT NULL CHECK(job_type IN ('discovery','enumerate','rescan')),
            status          TEXT DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
            config          TEXT,
            progress        TEXT,
            started_at      TIMESTAMPTZ,
            completed_at    TIMESTAMPTZ,
            buckets_found   INTEGER DEFAULT 0,
            buckets_open    INTEGER DEFAULT 0,
            files_indexed   INTEGER DEFAULT 0,
            names_checked   INTEGER DEFAULT 0,
            errors          TEXT,
            created_by      INTEGER REFERENCES users(id),
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS api_log (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id),
            endpoint        TEXT NOT NULL,
            method          TEXT DEFAULT 'GET',
            query_params    TEXT,
            ip_address      TEXT,
            user_agent      TEXT,
            response_status INTEGER,
            response_time_ms INTEGER,
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS watchlists (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id),
            name            TEXT NOT NULL,
            description     TEXT DEFAULT '',
            keywords        TEXT NOT NULL,
            companies       TEXT DEFAULT '[]',
            providers       TEXT DEFAULT '[]',
            is_active       BOOLEAN DEFAULT true,
            scan_interval_hours INTEGER DEFAULT 24,
            last_scan_at    TIMESTAMPTZ,
            next_scan_at    TIMESTAMPTZ,
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc'),
            updated_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              SERIAL PRIMARY KEY,
            watchlist_id    INTEGER REFERENCES watchlists(id) ON DELETE CASCADE,
            user_id         INTEGER REFERENCES users(id),
            alert_type      TEXT NOT NULL CHECK(alert_type IN ('new_bucket','new_files','status_change','sensitive_file','bucket_closed')),
            severity        TEXT DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),
            title           TEXT NOT NULL,
            description     TEXT,
            bucket_id       INTEGER REFERENCES buckets(id),
            file_id         INTEGER,
            is_read         BOOLEAN DEFAULT false,
            is_resolved     BOOLEAN DEFAULT false,
            resolved_at     TIMESTAMPTZ,
            metadata        TEXT,
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS monitored_assets (
            id              SERIAL PRIMARY KEY,
            watchlist_id    INTEGER REFERENCES watchlists(id) ON DELETE CASCADE,
            bucket_id       INTEGER REFERENCES buckets(id),
            first_detected  TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc'),
            last_checked    TIMESTAMPTZ,
            previous_status TEXT,
            current_status  TEXT,
            file_count_prev INTEGER DEFAULT 0,
            file_count_curr INTEGER DEFAULT 0,
            UNIQUE(watchlist_id, bucket_id)
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS webhook_configs (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id),
            name            TEXT NOT NULL,
            url             TEXT NOT NULL,
            secret          TEXT,
            event_types     TEXT DEFAULT '["critical","high"]',
            is_active       BOOLEAN DEFAULT true,
            last_triggered  TIMESTAMPTZ,
            failure_count   INTEGER DEFAULT 0,
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    op.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER NOT NULL REFERENCES users(id),
            token           TEXT UNIQUE NOT NULL,
            expires_at      TIMESTAMPTZ NOT NULL,
            used            BOOLEAN DEFAULT false,
            created_at      TIMESTAMPTZ DEFAULT (now() AT TIME ZONE 'utc')
        )
    """)
    # Indexes
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS idx_buckets_provider ON buckets(provider_id)",
        "CREATE INDEX IF NOT EXISTS idx_buckets_status ON buckets(status)",
        "CREATE INDEX IF NOT EXISTS idx_buckets_name ON buckets(name)",
        "CREATE INDEX IF NOT EXISTS idx_buckets_last_scanned ON buckets(last_scanned)",
        "CREATE INDEX IF NOT EXISTS idx_files_bucket ON files(bucket_id)",
        "CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension)",
        "CREATE INDEX IF NOT EXISTS idx_files_filename ON files(filename)",
        "CREATE INDEX IF NOT EXISTS idx_files_size ON files(size_bytes)",
        "CREATE INDEX IF NOT EXISTS idx_files_indexed ON files(indexed_at)",
        "CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key)",
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
        "CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status)",
        "CREATE INDEX IF NOT EXISTS idx_api_log_user ON api_log(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_api_log_created ON api_log(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_watchlists_user ON watchlists(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_watchlists_next_scan ON watchlists(next_scan_at)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_watchlist ON alerts(watchlist_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_unread ON alerts(user_id, is_read)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
        "CREATE INDEX IF NOT EXISTS idx_monitored_assets_wl ON monitored_assets(watchlist_id)",
        "CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhook_configs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_reset_tokens ON password_reset_tokens(token)",
    ]:
        op.execute(idx_sql)

    # Seed providers
    op.execute("""
        INSERT INTO providers (id, name, display_name, bucket_term, endpoint_pattern)
        VALUES
            (1, 'aws', 'Amazon Web Services', 'bucket', 'https://{name}.s3.{region}.amazonaws.com'),
            (2, 'azure', 'Microsoft Azure', 'container', 'https://{name}.blob.core.windows.net'),
            (3, 'gcp', 'Google Cloud Platform', 'bucket', 'https://storage.googleapis.com/{name}'),
            (4, 'digitalocean', 'DigitalOcean', 'space', 'https://{name}.{region}.digitaloceanspaces.com'),
            (5, 'alibaba', 'Alibaba Cloud', 'bucket', 'https://{name}.oss-{region}.aliyuncs.com')
        ON CONFLICT (id) DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS password_reset_tokens CASCADE")
    op.execute("DROP TABLE IF EXISTS webhook_configs CASCADE")
    op.execute("DROP TABLE IF EXISTS monitored_assets CASCADE")
    op.execute("DROP TABLE IF EXISTS alerts CASCADE")
    op.execute("DROP TABLE IF EXISTS watchlists CASCADE")
    op.execute("DROP TABLE IF EXISTS api_log CASCADE")
    op.execute("DROP TABLE IF EXISTS scan_jobs CASCADE")
    op.execute("DROP TABLE IF EXISTS files CASCADE")
    op.execute("DROP TABLE IF EXISTS buckets CASCADE")
    op.execute("DROP TABLE IF EXISTS users CASCADE")
    op.execute("DROP TABLE IF EXISTS providers CASCADE")
