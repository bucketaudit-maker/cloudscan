import asyncio
import random

from backend.app.scanners.engine import (
    BucketScanner,
    Provider,
    attribution_for_candidate,
    describe_database_target,
    generate_bucket_names,
)


def test_database_target_redacts_credentials():
    target = describe_database_target(
        "postgresql://cloudscan:top-secret@postgres.railway.internal:5432/railway"
    )

    assert target == "postgresql://postgres.railway.internal:5432/railway"
    assert "cloudscan" not in target
    assert "top-secret" not in target


def test_company_candidates_survive_small_scan_limit():
    names = generate_bucket_names(
        keywords=["backup"],
        companies=["Acme Corp"],
        max_names=10,
    )

    assert len(names) == 10
    assert names["acme-corp"] == "Acme Corp"
    assert all(company == "Acme Corp" for company in names.values())


def test_generic_candidates_are_not_attributed():
    names = generate_bucket_names(keywords=["backup"], max_names=10)

    assert len(names) == 10
    assert all(company == "" for company in names.values())


def test_generic_candidates_rotate_between_scheduled_runs():
    state = random.getstate()
    try:
        random.seed(1)
        first = generate_bucket_names(keywords=["backup", "assets"], max_names=100)
        random.seed(2)
        second = generate_bucket_names(keywords=["backup", "assets"], max_names=100)
    finally:
        random.setstate(state)

    assert set(first) != set(second)


def test_company_attribution_is_explicitly_inferred():
    source, confidence = attribution_for_candidate("acme-corp-backup", "Acme Corp")

    assert source == "scan_input_name_pattern"
    assert confidence == 0.35


class _FakeResponse:
    def __init__(self, status, body, headers=None):
        self.status = status
        self._body = body
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def text(self, errors="replace"):
        return self._body


class _FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, *args, **kwargs):
        return self.responses.pop(0)


def test_aws_checks_website_after_listing_access_is_denied():
    scanner = BucketScanner(concurrency=1, timeout=1)
    session = _FakeSession([
        _FakeResponse(403, "<Error><Code>AccessDenied</Code></Error>"),
        _FakeResponse(200, "<html>public site</html>"),
    ])

    async def fake_session():
        return session

    scanner._ensure_session = fake_session
    scanner._build_probe_urls = lambda *args: ["https://bucket-api", "http://bucket-site"]
    result = asyncio.run(scanner.check_bucket(Provider.AWS, "acme-public", "us-east-1"))

    assert result.status == "open"
    assert result.exposure_type == "public_website"
    assert result.evidence == {
        "method": "unauthenticated_http",
        "endpoint": "http://bucket-site",
        "response_status": 200,
        "signal": "unauthenticated_website_read",
        "confidence": 0.8,
    }


def test_public_listing_records_reproducible_evidence():
    scanner = BucketScanner(concurrency=1, timeout=1)
    body = """<ListBucketResult><Contents><Key>backup.sql</Key><Size>42</Size></Contents></ListBucketResult>"""
    session = _FakeSession([_FakeResponse(200, body)])

    async def fake_session():
        return session

    scanner._ensure_session = fake_session
    result = asyncio.run(scanner.check_bucket(Provider.GCP, "acme-data"))

    assert result.status == "open"
    assert result.exposure_type == "public_listing"
    assert result.file_count == 1
    assert result.evidence["signal"] == "unauthenticated_bucket_listing"
