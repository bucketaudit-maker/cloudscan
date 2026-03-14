"""
Database layer — PostgreSQL (primary) with tsvector full-text search; SQLite for tests.
"""
import json
import logging
import os
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
    logger.info(f"SQLite database initialized at {db_path}")
    return db_path


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — BUCKETS
# ═══════════════════════════════════════════════════════════════════

class BucketStore:
    @staticmethod
    def upsert(provider_id: int, name: str, region: str, url: str,
               status: str = "open", scan_time_ms: int = 0, metadata: dict = None) -> dict:
        with get_db() as db:
            now = datetime.now(timezone.utc).isoformat()
            sql = """
                INSERT INTO buckets (provider_id, name, region, url, status, first_seen, last_scanned, scan_time_ms, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(provider_id, name, region) DO UPDATE SET
                    status=excluded.status, last_scanned=excluded.last_scanned,
                    scan_time_ms=excluded.scan_time_ms,
                    url=COALESCE(excluded.url, buckets.url),
                    metadata=COALESCE(excluded.metadata, buckets.metadata)
            """ if settings.is_postgres else """
                INSERT INTO buckets (provider_id, name, region, url, status, first_seen, last_scanned, scan_time_ms, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(provider_id, name, region) DO UPDATE SET
                    status=excluded.status, last_scanned=excluded.last_scanned,
                    scan_time_ms=excluded.scan_time_ms,
                    url=COALESCE(excluded.url, url),
                    metadata=COALESCE(excluded.metadata, metadata)
            """
            db.execute(sql, (provider_id, name, region, url, status, now, now, scan_time_ms,
                             json.dumps(metadata) if metadata else None))
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
                 page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            q = """SELECT b.*, p.name as provider_name, p.display_name as provider_display
                   FROM buckets b JOIN providers p ON b.provider_id=p.id WHERE 1=1"""
            params = []
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
               page: int = 1, per_page: int = 50, regex: str = None) -> dict:
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
            db.execute("UPDATE alerts SET is_read=1 WHERE id=%s AND user_id=%s", (alert_id, user_id))

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
                "SELECT * FROM webhook_configs WHERE user_id=%s AND is_active=1",
                (user_id,),
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
                    "UPDATE webhook_configs SET is_active=0 WHERE id=%s", (webhook_id,)
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
