"""
Tests for CloudScan backend.
Run: python -m pytest backend/tests/ -v
"""
import json
import os
import sys
import tempfile

import pytest

# Isolate tests: use a temp SQLite DB (config reads DATABASE_URL)
_tmp = tempfile.mktemp(suffix=".db")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.main import create_app
from backend.app.models.database import (
    init_db,
    get_db,
    BucketStore,
    FileStore,
    ScanJobStore,
    WatchlistStore,
    AlertStore,
)
from backend.app.utils.auth import hash_password, verify_password, create_token, decode_token


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


@pytest.fixture
def auth_user(client):
    """Register and return (token, user_id) for first user."""
    r = client.post(
        "/api/v1/auth/register",
        json={"email": "user_a@test.com", "username": "usera", "password": "password123"},
    )
    assert r.status_code == 201
    data = r.get_json()
    return data["token"], data["user"]["id"]


@pytest.fixture
def auth_user_b(client):
    """Register and return (token, user_id) for second user (for authz tests)."""
    r = client.post(
        "/api/v1/auth/register",
        json={"email": "user_b@test.com", "username": "userb", "password": "password456"},
    )
    assert r.status_code == 201
    data = r.get_json()
    return data["token"], data["user"]["id"]


class TestDatabase:
    def test_init_db(self):
        path = init_db()
        assert os.path.exists(path)

    def test_providers_seeded(self):
        init_db()
        with get_db() as db:
            providers = db.execute("SELECT * FROM providers").fetchall()
            assert len(providers) == 5
            names = [p["name"] for p in providers]
            assert "aws" in names
            assert "azure" in names
            assert "gcp" in names

    def test_bucket_upsert(self):
        init_db()
        b = BucketStore.upsert(1, "test-bucket", "us-east-1", "https://test.s3.amazonaws.com", "open")
        assert b["name"] == "test-bucket"
        assert b["status"] == "open"
        # Upsert again should update
        b2 = BucketStore.upsert(1, "test-bucket", "us-east-1", "https://test.s3.amazonaws.com", "closed")
        assert b2["status"] == "closed"

    def test_file_insert_and_search(self):
        init_db()
        b = BucketStore.upsert(1, "search-test", "us-east-1", "https://test.s3.amazonaws.com", "open")
        FileStore.insert_batch(b["id"], [
            {"filepath": "config/database.json", "filename": "database.json", "extension": "json",
             "size_bytes": 1024, "url": "https://test/config/database.json"},
            {"filepath": "backups/users.sql", "filename": "users.sql", "extension": "sql",
             "size_bytes": 5000000, "url": "https://test/backups/users.sql"},
            {"filepath": ".env.production", "filename": ".env.production", "extension": "env",
             "size_bytes": 256, "url": "https://test/.env.production"},
        ])
        # Search by query
        results = FileStore.search(query="database")
        assert results["total"] >= 1

        # Search by extension
        results = FileStore.search(extensions=["sql"])
        assert results["total"] >= 1
        assert all(r["extension"] == "sql" for r in results["items"])

    def test_stats(self):
        init_db()
        stats = FileStore.get_stats()
        assert "total_files" in stats
        assert "total_buckets" in stats
        assert "providers" in stats

    def test_scan_job_lifecycle(self):
        init_db()
        job = ScanJobStore.create("discovery", {"keywords": ["test"]})
        assert job["status"] == "pending"
        ScanJobStore.update(job["id"], status="running")
        updated = ScanJobStore.get(job["id"])
        assert updated["status"] == "running"


class TestAuth:
    def test_password_hashing(self):
        h = hash_password("mypassword")
        assert verify_password("mypassword", h)
        assert not verify_password("wrongpassword", h)

    def test_jwt_tokens(self):
        token = create_token(1, "test@example.com", "free")
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == 1
        assert payload["email"] == "test@example.com"

    def test_invalid_token(self):
        assert decode_token("invalid.token") is None
        assert decode_token("") is None


class TestAPI:
    def test_health(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data["status"] == "ok"

    def test_stats(self, client):
        r = client.get("/api/v1/stats")
        assert r.status_code == 200
        data = r.get_json()
        assert "total_files" in data

    def test_providers(self, client):
        r = client.get("/api/v1/providers")
        assert r.status_code == 200
        data = r.get_json()
        assert len(data["items"]) == 5

    def test_register_and_login(self, client):
        # Register
        r = client.post("/api/v1/auth/register", json={
            "email": "test@test.com", "username": "testuser", "password": "password123"
        })
        assert r.status_code == 201
        data = r.get_json()
        assert "token" in data
        assert "api_key" in data
        assert data["api_key"].startswith("cs_")

        # Login
        r = client.post("/api/v1/auth/login", json={
            "email": "test@test.com", "password": "password123"
        })
        assert r.status_code == 200
        assert "token" in r.get_json()

        # Wrong password
        r = client.post("/api/v1/auth/login", json={
            "email": "test@test.com", "password": "wrong"
        })
        assert r.status_code == 401

    def test_search_requires_params(self, client):
        r = client.get("/api/v1/files")
        assert r.status_code == 400

    def test_search_with_query(self, client):
        r = client.get("/api/v1/files?q=test")
        assert r.status_code == 200
        data = r.get_json()
        assert "items" in data
        assert "total" in data

    def test_buckets_list(self, client):
        r = client.get("/api/v1/buckets")
        assert r.status_code == 200
        data = r.get_json()
        assert "items" in data

    def test_scan_requires_auth(self, client):
        r = client.post("/api/v1/scans", json={"keywords": ["test"]})
        assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# AUTHORIZATION (authz) — production security
# ═══════════════════════════════════════════════════════════════════


class TestAuthzMonitorRequiresAuth:
    """Monitor endpoints require authentication (auth_required_strict)."""

    def test_list_watchlists_unauthorized(self, client):
        r = client.get("/api/v1/monitor/watchlists")
        assert r.status_code == 401
        assert "error" in r.get_json()

    def test_create_watchlist_unauthorized(self, client):
        r = client.post(
            "/api/v1/monitor/watchlists",
            json={"name": "Test", "keywords": ["kw"]},
        )
        assert r.status_code == 401

    def test_dashboard_unauthorized(self, client):
        r = client.get("/api/v1/monitor/dashboard")
        assert r.status_code == 401

    def test_list_alerts_unauthorized(self, client):
        r = client.get("/api/v1/monitor/alerts")
        assert r.status_code == 401


class TestAuthzWatchlistOwnership:
    """User B cannot access or mutate user A's watchlist (IDOR)."""

    def test_get_watchlist_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        token_a, user_id_a = auth_user
        _token_b, _user_id_b = auth_user_b
        # User A creates a watchlist
        r = client.post(
            "/api/v1/monitor/watchlists",
            headers=_auth_headers(token_a),
            json={"name": "A's list", "keywords": ["secret"]},
        )
        assert r.status_code == 201
        wl_id = r.get_json()["id"]
        # User B tries to get it
        r = client.get(
            f"/api/v1/monitor/watchlists/{wl_id}",
            headers=_auth_headers(_token_b),
        )
        assert r.status_code == 404
        assert "error" in r.get_json()

    def test_update_watchlist_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        token_a, _ = auth_user
        token_b, _ = auth_user_b
        r = client.post(
            "/api/v1/monitor/watchlists",
            headers=_auth_headers(token_a),
            json={"name": "A's list", "keywords": ["x"]},
        )
        assert r.status_code == 201
        wl_id = r.get_json()["id"]
        r = client.put(
            f"/api/v1/monitor/watchlists/{wl_id}",
            headers=_auth_headers(token_b),
            json={"name": "Hacked"},
        )
        assert r.status_code == 404

    def test_delete_watchlist_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        token_a, _ = auth_user
        token_b, _ = auth_user_b
        r = client.post(
            "/api/v1/monitor/watchlists",
            headers=_auth_headers(token_a),
            json={"name": "A's list", "keywords": ["x"]},
        )
        assert r.status_code == 201
        wl_id = r.get_json()["id"]
        r = client.delete(
            f"/api/v1/monitor/watchlists/{wl_id}",
            headers=_auth_headers(token_b),
        )
        assert r.status_code == 404

    def test_trigger_scan_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        token_a, _ = auth_user
        token_b, _ = auth_user_b
        r = client.post(
            "/api/v1/monitor/watchlists",
            headers=_auth_headers(token_a),
            json={"name": "A's list", "keywords": ["x"]},
        )
        assert r.status_code == 201
        wl_id = r.get_json()["id"]
        r = client.post(
            f"/api/v1/monitor/watchlists/{wl_id}/scan",
            headers=_auth_headers(token_b),
        )
        assert r.status_code == 404


class TestAuthzAlertOwnership:
    """User B cannot mark read or resolve user A's alert."""

    def test_mark_alert_read_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        init_db()
        token_a, user_id_a = auth_user
        token_b, _ = auth_user_b
        wl = WatchlistStore.create(user_id_a, "A's list", ["x"], [], [], 24)
        alert = AlertStore.create(
            wl["id"], user_id_a, "new_bucket", "medium",
            "Test alert", "desc", None, None, None,
        )
        r = client.post(
            f"/api/v1/monitor/alerts/{alert['id']}/read",
            headers=_auth_headers(token_b),
        )
        assert r.status_code == 404

    def test_resolve_alert_forbidden_when_other_user(self, client, auth_user, auth_user_b):
        init_db()
        token_a, user_id_a = auth_user
        token_b, _ = auth_user_b
        wl = WatchlistStore.create(user_id_a, "A's list", ["x"], [], [], 24)
        alert = AlertStore.create(
            wl["id"], user_id_a, "new_bucket", "high",
            "Test", "", None, None, None,
        )
        r = client.post(
            f"/api/v1/monitor/alerts/{alert['id']}/resolve",
            headers=_auth_headers(token_b),
        )
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# CRITICAL PATH — auth, monitor, scans for production confidence
# ═══════════════════════════════════════════════════════════════════


class TestCriticalPathAuth:
    def test_me_with_valid_token(self, client, auth_user):
        token, user = auth_user
        r = client.get("/api/v1/auth/me", headers=_auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        assert data["id"] == user
        assert "email" in data and "username" in data

    def test_me_without_token(self, client):
        r = client.get("/api/v1/auth/me")
        assert r.status_code == 401

    def test_forgot_password_accepts_email(self, client):
        r = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "nobody@example.com"},
        )
        assert r.status_code == 200
        data = r.get_json()
        assert "message" in data

    def test_reset_password_invalid_token(self, client):
        r = client.post(
            "/api/v1/auth/reset-password",
            json={"token": "invalid-token", "password": "newpass123"},
        )
        assert r.status_code == 400
        assert "error" in r.get_json()


class TestCriticalPathWatchlist:
    def test_create_list_get_delete(self, client, auth_user):
        token, _ = auth_user
        r = client.post(
            "/api/v1/monitor/watchlists",
            headers=_auth_headers(token),
            json={"name": "My Watchlist", "keywords": ["company", "backup"]},
        )
        assert r.status_code == 201
        data = r.get_json()
        assert data["name"] == "My Watchlist"
        wl_id = data["id"]
        r = client.get(f"/api/v1/monitor/watchlists/{wl_id}", headers=_auth_headers(token))
        assert r.status_code == 200
        assert r.get_json()["name"] == "My Watchlist"
        r = client.get("/api/v1/monitor/watchlists", headers=_auth_headers(token))
        assert r.status_code == 200
        assert any(w["id"] == wl_id for w in r.get_json()["items"])
        r = client.delete(f"/api/v1/monitor/watchlists/{wl_id}", headers=_auth_headers(token))
        assert r.status_code == 200
        r = client.get("/api/v1/monitor/watchlists", headers=_auth_headers(token))
        assert not any(w["id"] == wl_id for w in r.get_json()["items"])

    def test_dashboard_returns_counts(self, client, auth_user):
        token, _ = auth_user
        r = client.get("/api/v1/monitor/dashboard", headers=_auth_headers(token))
        assert r.status_code == 200
        data = r.get_json()
        assert "watchlists" in data
        assert "unread_alerts" in data
        assert "alerts_by_severity" in data


class TestCriticalPathScans:
    def test_create_scan_with_auth(self, client, auth_user):
        token, _ = auth_user
        r = client.post(
            "/api/v1/scans",
            headers=_auth_headers(token),
            json={"keywords": ["test"], "companies": []},
        )
        assert r.status_code == 202
        data = r.get_json()
        assert "id" in data
        job_id = data["id"]
        r = client.get(f"/api/v1/scans/{job_id}", headers=_auth_headers(token))
        assert r.status_code == 200
        assert r.get_json()["status"] in ("pending", "running", "completed", "failed", "cancelled")


class TestCriticalPathAlerts:
    def test_mark_own_alert_read(self, client, auth_user):
        init_db()
        token, user_id = auth_user
        wl = WatchlistStore.create(user_id, "W", ["x"], [], [], 24)
        alert = AlertStore.create(
            wl["id"], user_id, "new_bucket", "medium",
            "My alert", "", None, None, None,
        )
        r = client.post(
            f"/api/v1/monitor/alerts/{alert['id']}/read",
            headers=_auth_headers(token),
        )
        assert r.status_code == 200
        assert r.get_json().get("message") == "Marked read"

    def test_resolve_own_alert(self, client, auth_user):
        init_db()
        token, user_id = auth_user
        wl = WatchlistStore.create(user_id, "W", ["x"], [], [], 24)
        alert = AlertStore.create(
            wl["id"], user_id, "new_bucket", "low",
            "Alert", "", None, None, None,
        )
        r = client.post(
            f"/api/v1/monitor/alerts/{alert['id']}/resolve",
            headers=_auth_headers(token),
        )
        assert r.status_code == 200


def teardown_module():
    if os.path.exists(_tmp):
        os.remove(_tmp)
