"""
Tests for CloudScan backend.
Run: python -m pytest backend/tests/ -v
"""
import json
import os
import sys
import tempfile

import pytest

# Point DB to temp file
_tmp = tempfile.mktemp(suffix=".db")
os.environ["CLOUDSCAN_DB"] = _tmp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.app.main import create_app
from backend.app.models.database import init_db, get_db, BucketStore, FileStore, ScanJobStore
from backend.app.utils.auth import hash_password, verify_password, create_token, decode_token


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


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


def teardown_module():
    if os.path.exists(_tmp):
        os.remove(_tmp)
