"""
Database layer — SQLite with FTS5 full-text search.
Production: swap to PostgreSQL with pg_trgm / Elasticsearch.

Tables: providers, buckets, files, files_fts, scan_jobs, users, api_log
"""
import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from backend.app.config import settings

logger = logging.getLogger(__name__)

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


def init_db() -> str:
    """Initialize database, create tables, seed providers."""
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
    logger.info(f"Database initialized at {db_path}")
    return db_path


@contextmanager
def get_db():
    """Thread-safe database connection context manager."""
    conn = sqlite3.connect(get_db_path(), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — BUCKETS
# ═══════════════════════════════════════════════════════════════════

class BucketStore:
    @staticmethod
    def upsert(provider_id: int, name: str, region: str, url: str,
               status: str = "open", scan_time_ms: int = 0, metadata: dict = None) -> dict:
        with get_db() as db:
            now = datetime.utcnow().isoformat()
            db.execute("""
                INSERT INTO buckets (provider_id, name, region, url, status, first_seen, last_scanned, scan_time_ms, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider_id, name, region) DO UPDATE SET
                    status=excluded.status, last_scanned=excluded.last_scanned,
                    scan_time_ms=excluded.scan_time_ms,
                    url=COALESCE(excluded.url, url),
                    metadata=COALESCE(excluded.metadata, metadata)
            """, (provider_id, name, region, url, status, now, now, scan_time_ms,
                  json.dumps(metadata) if metadata else None))
            row = db.execute(
                "SELECT * FROM buckets WHERE provider_id=? AND name=? AND region=?",
                (provider_id, name, region),
            ).fetchone()
            return dict(row) if row else {}

    @staticmethod
    def get(bucket_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("""
                SELECT b.*, p.name as provider_name, p.display_name as provider_display
                FROM buckets b JOIN providers p ON b.provider_id=p.id WHERE b.id=?
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
                q += " AND p.name=?"; params.append(provider)
            if status:
                q += " AND b.status=?"; params.append(status)
            if search:
                q += " AND b.name LIKE ?"; params.append(f"%{search}%")

            total = db.execute(f"SELECT COUNT(*) FROM ({q})", params).fetchone()[0]
            q += " ORDER BY b.last_scanned DESC NULLS LAST LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])
            rows = db.execute(q, params).fetchall()
            return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}

    @staticmethod
    def update_counts(bucket_id: int):
        with get_db() as db:
            r = db.execute(
                "SELECT COUNT(*) as cnt, COALESCE(SUM(size_bytes),0) as total FROM files WHERE bucket_id=?",
                (bucket_id,),
            ).fetchone()
            db.execute(
                "UPDATE buckets SET file_count=?, total_size_bytes=? WHERE id=?",
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
            now = datetime.utcnow().isoformat()
            cursor = db.executemany("""
                INSERT OR IGNORE INTO files
                (bucket_id, filepath, filename, extension, size_bytes, last_modified, etag, content_type, url, indexed_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(
                bucket_id, f["filepath"], f["filename"], f.get("extension", ""),
                f.get("size_bytes", 0), f.get("last_modified"), f.get("etag"),
                f.get("content_type", ""), f["url"], now,
                json.dumps(f.get("metadata")) if f.get("metadata") else None,
            ) for f in files_list])
            count = cursor.rowcount
        BucketStore.update_counts(bucket_id)
        return count

    @staticmethod
    def search(query: str = "", extensions: list = None, exclude_extensions: list = None,
               min_size: int = None, max_size: int = None, provider: str = None,
               bucket_name: str = None, sort: str = "relevance",
               page: int = 1, per_page: int = 50) -> dict:
        with get_db() as db:
            base = """
                SELECT f.*, b.name as bucket_name, b.url as bucket_url, b.region,
                    p.name as provider_name, p.display_name as provider_display
                FROM files f
                JOIN buckets b ON f.bucket_id=b.id
                JOIN providers p ON b.provider_id=p.id
            """
            wheres, params = [], []

            if query:
                base += " JOIN files_fts ON files_fts.rowid=f.id"
                # Convert user query to FTS5 syntax
                fts_terms = []
                for term in query.split():
                    if term.startswith("-"):
                        fts_terms.append(f"NOT {term[1:]}")
                    elif term.startswith("*."):
                        fts_terms.append(term[2:])
                    else:
                        fts_terms.append(term)
                fts_q = " ".join(fts_terms)
                wheres.append("files_fts MATCH ?")
                params.append(fts_q)

            if extensions:
                ph = ",".join("?" for _ in extensions)
                wheres.append(f"f.extension IN ({ph})")
                params.extend([e.lower().lstrip(".") for e in extensions if e])

            if exclude_extensions:
                ph = ",".join("?" for _ in exclude_extensions)
                wheres.append(f"f.extension NOT IN ({ph})")
                params.extend([e.lower().lstrip(".") for e in exclude_extensions if e])

            if min_size is not None:
                wheres.append("f.size_bytes >= ?"); params.append(min_size)
            if max_size is not None:
                wheres.append("f.size_bytes <= ?"); params.append(max_size)
            if provider:
                wheres.append("p.name = ?"); params.append(provider)
            if bucket_name:
                wheres.append("b.name LIKE ?"); params.append(f"%{bucket_name}%")

            if wheres:
                base += " WHERE " + " AND ".join(wheres)

            total = db.execute(f"SELECT COUNT(*) FROM ({base})", params).fetchone()[0]

            sort_map = {
                "relevance": "ORDER BY f.id DESC",
                "size_asc": "ORDER BY f.size_bytes ASC",
                "size_desc": "ORDER BY f.size_bytes DESC",
                "newest": "ORDER BY f.indexed_at DESC",
                "oldest": "ORDER BY f.indexed_at ASC",
                "filename": "ORDER BY f.filename ASC",
            }
            base += f" {sort_map.get(sort, 'ORDER BY f.id DESC')} LIMIT ? OFFSET ?"
            params.extend([per_page, (page - 1) * per_page])

            rows = db.execute(base, params).fetchall()
            return {
                "items": [dict(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
                "query": query,
            }

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


# ═══════════════════════════════════════════════════════════════════
# DATA ACCESS — SCAN JOBS
# ═══════════════════════════════════════════════════════════════════

class ScanJobStore:
    @staticmethod
    def create(job_type: str, config: dict, created_by: int = None) -> dict:
        with get_db() as db:
            cursor = db.execute("""
                INSERT INTO scan_jobs (job_type, status, config, created_by)
                VALUES (?, 'pending', ?, ?)
            """, (job_type, json.dumps(config), created_by))
            row = db.execute("SELECT * FROM scan_jobs WHERE id=?", (cursor.lastrowid,)).fetchone()
            return dict(row)

    @staticmethod
    def get(job_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()
            return dict(row) if row else None

    @staticmethod
    def update(job_id: int, **kwargs):
        with get_db() as db:
            sets = ", ".join(f"{k}=?" for k in kwargs)
            vals = list(kwargs.values())
            vals.append(job_id)
            db.execute(f"UPDATE scan_jobs SET {sets} WHERE id=?", vals)

    @staticmethod
    def list_recent(limit: int = 50) -> list[dict]:
        with get_db() as db:
            rows = db.execute("SELECT * FROM scan_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]
