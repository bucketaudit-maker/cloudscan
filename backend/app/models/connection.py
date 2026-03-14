"""
Database connection abstraction: PostgreSQL (primary) and SQLite (tests).
Uses %s placeholders in SQL; converts to ? for SQLite.
"""
import re
import sqlite3
from contextlib import contextmanager
from typing import Any, Optional

from backend.app.config import settings


class _Row(dict):
    """Dict subclass that also supports row[0], row[1] for positional access (e.g. COUNT(*))."""

    def __init__(self, d: dict):
        super().__init__(d if d else {})
        self._vals = list(self.values())

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key] if 0 <= key < len(self._vals) else None
        return super().__getitem__(key)

# Optional psycopg2 (required for Postgres)
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False


def _sqlite_convert_placeholders(sql: str) -> str:
    """Convert %s placeholders to ? for SQLite."""
    return re.sub(r"%s", "?", sql)


class _SqliteWrapper:
    """Wrapper around sqlite3 connection: %s in SQL converted to ?."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        self._cursor: Optional[sqlite3.Cursor] = None
        self._lastrowid: Optional[int] = None

    def execute(self, sql: str, params: tuple = ()) -> "_SqliteWrapper":
        sql = _sqlite_convert_placeholders(sql)
        self._cursor = self._conn.execute(sql, params)
        self._lastrowid = self._cursor.lastrowid
        return self

    def executemany(self, sql: str, params_list: list) -> "_SqliteWrapper":
        sql = _sqlite_convert_placeholders(sql)
        self._cursor = self._conn.executemany(sql, params_list)
        self._lastrowid = self._cursor.lastrowid if self._cursor.rowcount == 1 else None
        return self

    def fetchone(self) -> Optional[dict]:
        if self._cursor is None:
            return None
        row = self._cursor.fetchone()
        return _Row(dict(row)) if row else None

    def fetchall(self) -> list:
        if self._cursor is None:
            return []
        return [_Row(dict(r)) for r in self._cursor.fetchall()]

    @property
    def lastrowid(self) -> Optional[int]:
        return self._lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount if self._cursor else 0

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


class _PostgresWrapper:
    """Wrapper around psycopg2 connection; INSERT gets RETURNING id for lastrowid."""

    def __init__(self, conn):
        self._conn = conn
        self._cursor = None
        self._lastrowid: Optional[int] = None

    def execute(self, sql: str, params: tuple = ()) -> "_PostgresWrapper":
        sql_strip = sql.strip().upper()
        # Single-row INSERT without RETURNING and without ON CONFLICT: add RETURNING id for lastrowid
        if (
            sql_strip.startswith("INSERT")
            and "RETURNING" not in sql.upper()
            and "ON CONFLICT" not in sql.upper()
        ):
            sql = sql.rstrip(";").strip() + " RETURNING id"
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        self._cursor.execute(sql, params)
        if sql_strip.startswith("INSERT") and "RETURNING" in sql:
            row = self._cursor.fetchone()
            self._lastrowid = int(row["id"]) if row and "id" in row else None
        else:
            self._lastrowid = None
        return self

    def executemany(self, sql: str, params_list: list) -> "_PostgresWrapper":
        self._cursor = self._conn.cursor(cursor_factory=RealDictCursor)
        self._cursor.executemany(sql, params_list)
        self._lastrowid = None
        return self

    def fetchone(self) -> Optional[dict]:
        if self._cursor is None:
            return None
        row = self._cursor.fetchone()
        return _Row(dict(row)) if row else None

    def fetchall(self) -> list:
        if self._cursor is None:
            return []
        return [_Row(dict(r)) for r in self._cursor.fetchall()]

    @property
    def lastrowid(self) -> Optional[int]:
        return self._lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount if self._cursor else 0

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        if self._cursor:
            self._cursor.close()
        self._conn.close()


@contextmanager
def get_db():
    """Thread-safe database connection. Yields a wrapper with execute(), fetchone(), fetchall(), executemany(), lastrowid, rowcount."""
    if settings.is_postgres:
        if not _HAS_PSYCOPG2:
            raise RuntimeError("PostgreSQL is configured but psycopg2 is not installed. pip install psycopg2-binary")
        conn = psycopg2.connect(settings.DATABASE_URL)
        wrapper = _PostgresWrapper(conn)
    else:
        conn = sqlite3.connect(settings.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.create_function("REGEXP", 2, lambda pattern, string: bool(re.search(pattern, string or "")))
        wrapper = _SqliteWrapper(conn)

    try:
        yield wrapper
        wrapper.commit()
    except Exception:
        wrapper.rollback()
        raise
    finally:
        wrapper.close()
