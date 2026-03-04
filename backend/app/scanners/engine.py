"""
Multi-Provider Async Bucket Scanner Engine.

Discovers and enumerates publicly accessible cloud storage across:
  - AWS S3
  - Azure Blob Storage
  - Google Cloud Storage
  - DigitalOcean Spaces
  - Alibaba Cloud OSS

Features:
  - Keyword-based name generation with smart permutations
  - Async concurrent HTTP probing (configurable concurrency)
  - XML listing parser with pagination support
  - Real-time progress callbacks for WebSocket streaming
  - Automatic file filtering (skip images, fonts, logs)
"""
import asyncio
import hashlib
import json
import logging
import os
import random
import re
import string
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Callable, Optional
from urllib.parse import quote

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore — only needed when actually scanning

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
# PROVIDER DEFINITIONS
# ═══════════════════════════════════════════════════════════════════

class Provider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    ALIBABA = "alibaba"


PROVIDER_DB_IDS = {
    Provider.AWS: 1, Provider.AZURE: 2, Provider.GCP: 3,
    Provider.DIGITALOCEAN: 4, Provider.ALIBABA: 5,
}

PROVIDER_CONFIGS = {
    Provider.AWS: {
        "url_templates": [
            "https://{name}.s3.amazonaws.com",
            "https://{name}.s3.{region}.amazonaws.com",
        ],
        "regions": [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            "ap-south-1", "sa-east-1", "ca-central-1",
        ],
        "list_marker": "<ListBucketResult",
        "denied_marker": "AccessDenied",
        "missing_marker": "NoSuchBucket",
    },
    Provider.AZURE: {
        "url_templates": [
            "https://{name}.blob.core.windows.net/$root?restype=container&comp=list",
        ],
        "regions": [""],
        "list_marker": "<EnumerationResults",
        "denied_marker": "AuthenticationFailed",
        "missing_marker": "ContainerNotFound",
    },
    Provider.GCP: {
        "url_templates": ["https://storage.googleapis.com/{name}"],
        "regions": [""],
        "list_marker": "<ListBucketResult",
        "denied_marker": "AccessDenied",
        "missing_marker": "NoSuchBucket",
    },
    Provider.DIGITALOCEAN: {
        "url_templates": ["https://{name}.{region}.digitaloceanspaces.com"],
        "regions": ["nyc3", "sfo3", "ams3", "sgp1", "fra1", "syd1"],
        "list_marker": "<ListBucketResult",
        "denied_marker": "AccessDenied",
        "missing_marker": "NoSuchBucket",
    },
    Provider.ALIBABA: {
        "url_templates": ["https://{name}.oss-{region}.aliyuncs.com"],
        "regions": ["cn-hangzhou", "cn-shanghai", "cn-beijing", "us-west-1", "us-east-1", "ap-southeast-1", "eu-central-1"],
        "list_marker": "<ListBucketResult",
        "denied_marker": "AccessDenied",
        "missing_marker": "NoSuchBucket",
    },
}

# File extensions to skip during indexing (uninteresting noise)
SKIP_EXTENSIONS = frozenset({
    "png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp", "svg", "ico",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm",
    "DS_Store", "thumbs.db",
})


# ═══════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScanProgress:
    """Real-time scan progress for WebSocket streaming."""
    job_id: int = 0
    phase: str = "idle"  # generating, scanning, enumerating, complete
    provider: str = ""
    names_total: int = 0
    names_checked: int = 0
    buckets_found: int = 0
    buckets_open: int = 0
    files_indexed: int = 0
    current_bucket: str = ""
    errors: int = 0
    elapsed_ms: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class BucketResult:
    provider: str
    name: str
    url: str
    region: str = ""
    status: str = "unknown"
    file_count: int = 0
    files: list = field(default_factory=list)
    error: str = ""
    scan_time_ms: int = 0

    def to_dict(self):
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════
# NAME GENERATION
# ═══════════════════════════════════════════════════════════════════

COMMON_WORDS = [
    "backup", "data", "dev", "staging", "prod", "production", "test", "testing",
    "static", "assets", "media", "uploads", "public", "private", "config",
    "logs", "temp", "tmp", "archive", "old", "new", "web", "app", "api",
    "cdn", "images", "files", "docs", "documents", "reports", "db", "database",
    "dump", "export", "import", "share", "shared", "internal", "external",
    "admin", "cms", "content", "resources", "download", "storage", "store",
    "secrets", "keys", "credentials", "terraform", "deploy", "release",
    "beta", "alpha", "legacy", "migration", "snapshot", "replica",
]

SUFFIXES = [
    "backup", "bak", "data", "dev", "staging", "prod", "bucket", "store",
    "storage", "assets", "static", "public", "private", "files", "media",
    "uploads", "archive", "db", "logs", "2023", "2024", "2025", "2026", "test",
]

SEPARATORS = ["-", ".", "_", ""]


def generate_bucket_names(
    keywords: list[str] = None,
    companies: list[str] = None,
    max_names: int = 5000,
) -> list[str]:
    """Generate candidate bucket names using multiple strategies."""
    names = set()

    # Strategy 1: Common word combinations
    for word in COMMON_WORDS[:25]:
        for suffix in SUFFIXES[:18]:
            if word == suffix:
                continue
            for sep in SEPARATORS:
                names.add(f"{word}{sep}{suffix}")

    # Strategy 2: Keyword-based
    if keywords:
        for kw in keywords:
            kw = kw.lower().strip()
            if not kw:
                continue
            names.add(kw)
            for word in COMMON_WORDS:
                for sep in SEPARATORS[:3]:
                    names.add(f"{kw}{sep}{word}")
                    names.add(f"{word}{sep}{kw}")

    # Strategy 3: Company name variants
    if companies:
        for company in companies:
            c = re.sub(r"[^a-z0-9]", "-", company.lower().strip()).strip("-")
            if not c:
                continue
            names.add(c)
            for suffix in SUFFIXES:
                for sep in SEPARATORS[:3]:
                    names.add(f"{c}{sep}{suffix}")
            # Common patterns: company-env, company-service-env
            for env in ["dev", "staging", "prod", "test"]:
                names.add(f"{c}-{env}")
                for svc in ["api", "web", "app", "data", "ml"]:
                    names.add(f"{c}-{svc}-{env}")

    # Strategy 4: Random alphanumeric
    for _ in range(min(200, max_names // 20)):
        length = random.randint(6, 14)
        names.add("".join(random.choices(string.ascii_lowercase + string.digits, k=length)))

    # Validate bucket names (S3 rules: 3-63 chars, lowercase, alphanumeric + hyphen + dot)
    valid = set()
    for name in names:
        name = re.sub(r"[^a-z0-9.\-]", "-", name.lower())
        name = re.sub(r"-+", "-", name).strip("-.")
        if 3 <= len(name) <= 63 and not name.startswith("xn--") and ".." not in name:
            valid.add(name)

    result = list(valid)[:max_names]
    logger.info(f"Generated {len(result)} valid bucket name candidates")
    return result


# ═══════════════════════════════════════════════════════════════════
# SCANNER CORE
# ═══════════════════════════════════════════════════════════════════

class BucketScanner:
    """Async multi-provider bucket scanner with progress tracking."""

    def __init__(self, concurrency: int = 50, timeout: int = 10, user_agent: str = None):
        if aiohttp is None:
            raise RuntimeError("aiohttp is required for scanning. Install: pip install aiohttp")
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent or "CloudScan/1.0 (Security Research)"
        self.semaphore = asyncio.Semaphore(concurrency)
        self._session = None
        self.progress = ScanProgress()

    async def _ensure_session(self) -> "aiohttp.ClientSession":
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=self.concurrency, ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.25)  # Allow graceful close

    def _build_url(self, provider: Provider, name: str, region: str) -> str:
        cfg = PROVIDER_CONFIGS[provider]
        template = cfg["url_templates"][0]
        if "{region}" in template and region:
            return template.format(name=name, region=region)
        elif "{region}" in template:
            return template.format(name=name, region=cfg["regions"][0] if cfg["regions"] else "")
        return template.format(name=name)

    async def check_bucket(self, provider: Provider, name: str, region: str = "") -> BucketResult:
        """Probe a single bucket for accessibility."""
        cfg = PROVIDER_CONFIGS[provider]
        url = self._build_url(provider, name, region)
        result = BucketResult(provider=provider.value, name=name, url=url, region=region)
        start = time.monotonic()

        try:
            async with self.semaphore:
                session = await self._ensure_session()
                async with session.get(url, allow_redirects=True, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    result.scan_time_ms = int((time.monotonic() - start) * 1000)

                    if resp.status == 200 and cfg["list_marker"] in body:
                        result.status = "open"
                        result.files = self._parse_listing(body, url, name)
                        result.file_count = len(result.files)
                    elif resp.status == 403 or cfg["denied_marker"] in body:
                        result.status = "closed"
                    elif resp.status == 404 or cfg["missing_marker"] in body:
                        result.status = "not_found"
                    elif resp.status == 200:
                        result.status = "partial"
                    else:
                        result.status = "not_found"

        except asyncio.TimeoutError:
            result.status = "error"
            result.error = "timeout"
        except aiohttp.ClientError as e:
            result.status = "error"
            result.error = str(e)[:200]
        except Exception as e:
            result.status = "error"
            result.error = f"unexpected: {str(e)[:150]}"

        return result

    def _parse_listing(self, xml_text: str, base_url: str, bucket_name: str) -> list[dict]:
        """Parse S3/GCS/Alibaba XML listing into file entries."""
        files = []
        try:
            clean = re.sub(r'\s+xmlns\s*=\s*"[^"]*"', "", xml_text)
            root = ET.fromstring(clean)

            for item in root.findall(".//Contents"):
                key_el = item.find("Key")
                if key_el is None or not key_el.text:
                    continue
                key = key_el.text
                if key.endswith("/"):
                    continue

                filename = key.split("/")[-1]
                ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

                if ext in SKIP_EXTENSIONS:
                    continue

                size_el = item.find("Size")
                mod_el = item.find("LastModified")
                etag_el = item.find("ETag")

                files.append({
                    "filepath": key,
                    "filename": filename,
                    "extension": ext,
                    "size_bytes": int(size_el.text) if size_el is not None and size_el.text else 0,
                    "last_modified": mod_el.text if mod_el is not None else "",
                    "etag": (etag_el.text or "").strip('"') if etag_el is not None else "",
                    "content_type": "",
                    "url": f"{base_url.rstrip('/')}/{quote(key, safe='/')}",
                })
        except ET.ParseError as e:
            logger.warning(f"XML parse error for {bucket_name}: {e}")

        return files

    async def run_discovery(
        self,
        providers: list[Provider] = None,
        keywords: list[str] = None,
        companies: list[str] = None,
        max_names: int = 1000,
        regions_per_provider: int = 3,
        on_progress: Callable[[ScanProgress], None] = None,
        on_result: Callable[[BucketResult], None] = None,
    ) -> list[BucketResult]:
        """
        Full discovery scan. Yields results via callbacks for real-time streaming.

        Args:
            providers: List of providers to scan (default: all)
            keywords: Keywords for name generation
            companies: Company names for targeted scanning
            max_names: Maximum candidate names to generate
            regions_per_provider: How many regions to try per provider
            on_progress: Called with ScanProgress updates
            on_result: Called for each found bucket (open/closed/partial)
        """
        if providers is None:
            providers = list(Provider)

        self.progress = ScanProgress(phase="generating")
        if on_progress:
            on_progress(self.progress)

        names = generate_bucket_names(keywords=keywords, companies=companies, max_names=max_names)
        start_time = time.monotonic()

        self.progress.names_total = sum(
            len(names) * min(len(PROVIDER_CONFIGS[p]["regions"]) or 1, regions_per_provider)
            for p in providers
        )
        self.progress.phase = "scanning"

        all_results = []

        for provider in providers:
            cfg = PROVIDER_CONFIGS[provider]
            regions = (cfg["regions"] or [""])[:regions_per_provider]
            self.progress.provider = provider.value

            if on_progress:
                on_progress(self.progress)

            # Build tasks for this provider
            tasks = []
            for name in names:
                for region in regions:
                    tasks.append(self.check_bucket(provider, name, region))

            # Process with bounded concurrency
            for coro in asyncio.as_completed(tasks):
                result = await coro
                self.progress.names_checked += 1
                self.progress.elapsed_ms = int((time.monotonic() - start_time) * 1000)

                if result.status in ("open", "closed", "partial"):
                    self.progress.buckets_found += 1
                    if result.status == "open":
                        self.progress.buckets_open += 1
                        self.progress.files_indexed += result.file_count
                        self.progress.current_bucket = result.name
                    all_results.append(result)

                    if on_result:
                        on_result(result)
                elif result.status == "error":
                    self.progress.errors += 1

                # Emit progress every 50 checks
                if self.progress.names_checked % 50 == 0 and on_progress:
                    on_progress(self.progress)

        self.progress.phase = "complete"
        self.progress.elapsed_ms = int((time.monotonic() - start_time) * 1000)
        if on_progress:
            on_progress(self.progress)

        logger.info(
            f"Scan complete: {self.progress.names_checked} checked, "
            f"{self.progress.buckets_found} found, {self.progress.buckets_open} open, "
            f"{self.progress.files_indexed} files, {self.progress.errors} errors, "
            f"{self.progress.elapsed_ms}ms"
        )

        return all_results


# ═══════════════════════════════════════════════════════════════════
# DEEP ENUMERATION (paginated bucket crawl)
# ═══════════════════════════════════════════════════════════════════

async def enumerate_bucket_deep(
    provider: Provider, bucket_name: str, region: str = "",
    max_keys: int = 100000,
    on_progress: Callable = None,
) -> list[dict]:
    """Deep-crawl a known-open bucket with pagination (up to max_keys files)."""
    scanner = BucketScanner(concurrency=5, timeout=30)
    base_url = scanner._build_url(provider, bucket_name, region)
    all_files = []
    marker = ""
    page = 0

    try:
        session = await scanner._ensure_session()
        while True:
            page += 1
            params = {"max-keys": "1000"}
            if marker:
                params["marker"] = marker

            try:
                async with session.get(base_url, params=params, ssl=False) as resp:
                    if resp.status != 200:
                        break
                    text = await resp.text(errors="replace")
            except Exception as e:
                logger.warning(f"Enumeration page {page} failed for {bucket_name}: {e}")
                break

            files = scanner._parse_listing(text, base_url, bucket_name)
            all_files.extend(files)

            if on_progress:
                on_progress({"bucket": bucket_name, "files_so_far": len(all_files), "page": page})

            # Check for truncation
            clean = re.sub(r'\s+xmlns\s*=\s*"[^"]*"', "", text)
            try:
                root = ET.fromstring(clean)
                trunc = root.find("IsTruncated")
                if trunc is not None and trunc.text == "true":
                    nm = root.find("NextMarker")
                    if nm is not None and nm.text:
                        marker = nm.text
                    elif files:
                        marker = files[-1]["filepath"]
                    else:
                        break
                else:
                    break
            except ET.ParseError:
                break

            if len(all_files) >= max_keys:
                logger.info(f"Reached max_keys ({max_keys}) for {bucket_name}")
                break

    finally:
        await scanner.close()

    logger.info(f"Enumerated {len(all_files)} files from {bucket_name} ({page} pages)")
    return all_files
