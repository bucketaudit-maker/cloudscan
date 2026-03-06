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

    # Strategy 5: Broader synthetic patterns to better fill max_names, even without companies
    seeds = []
    if keywords:
        seeds.extend([k.lower().strip() for k in keywords if k and k.strip()])
    seeds.extend(COMMON_WORDS[:40])
    seeds = [re.sub(r"[^a-z0-9.\-]", "-", s) for s in seeds if s]
    years = ["2022", "2023", "2024", "2025", "2026", "01", "1", "dev", "prod", "staging", "test"]

    attempts = 0
    while len(names) < max_names and attempts < (max_names * 30):
        attempts += 1
        a = random.choice(seeds)
        b = random.choice(SUFFIXES)
        sep = random.choice(SEPARATORS[:3])
        pattern = random.randint(0, 4)
        if pattern == 0:
            candidate = f"{a}{sep}{b}"
        elif pattern == 1:
            candidate = f"{a}{sep}{random.choice(years)}"
        elif pattern == 2:
            candidate = f"{a}{sep}{b}{sep}{random.choice(years)}"
        elif pattern == 3:
            candidate = f"{random.choice(years)}{sep}{a}{sep}{b}"
        else:
            suffix_digits = random.randint(1, 9999)
            candidate = f"{a}{sep}{b}{suffix_digits}"
        names.add(candidate)

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
        templates = cfg["url_templates"]

        # Prefer a region-aware template when a region is provided.
        if region:
            for template in templates:
                if "{region}" in template:
                    return template.format(name=name, region=region)

        # Otherwise, prefer a global/non-region template.
        for template in templates:
            if "{region}" not in template:
                return template.format(name=name)

        # Fallback for providers that only support region-aware hostnames.
        template = templates[0]
        fallback_region = region or (cfg["regions"][0] if cfg["regions"] else "")
        return template.format(name=name, region=fallback_region)

    def _build_probe_urls(self, provider: Provider, name: str, region: str) -> list[str]:
        """Return ordered candidate URLs to probe for a bucket."""
        if provider != Provider.AWS:
            return [self._build_url(provider, name, region)]

        # AWS S3 API endpoints return 404 for all unauthenticated requests
        # (anti-enumeration). Use website endpoints which still return
        # distinct responses: 200 (open), 403 (private), 400 (wrong region),
        # 404+NoSuchWebsiteConfiguration (exists, no website config),
        # 404+NoSuchBucket (truly doesn't exist).
        urls = []
        if region:
            # Both website URL styles (dash-style and dot-style)
            urls.append(f"http://{name}.s3-website-{region}.amazonaws.com")
            urls.append(f"http://{name}.s3-website.{region}.amazonaws.com")
        # S3 API endpoints as fallback (still useful for open/listable buckets)
        urls.append(f"https://{name}.s3.amazonaws.com")

        # De-duplicate while preserving order.
        seen = set()
        deduped = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                deduped.append(u)
        return deduped

    async def check_bucket(self, provider: Provider, name: str, region: str = "") -> BucketResult:
        """Probe a single bucket for accessibility."""
        cfg = PROVIDER_CONFIGS[provider]
        url = self._build_url(provider, name, region)
        result = BucketResult(provider=provider.value, name=name, url=url, region=region)
        start = time.monotonic()

        try:
            async with self.semaphore:
                session = await self._ensure_session()
                candidate_urls = self._build_probe_urls(provider, name, region)
                any_not_found = False
                last_error = ""

                for probe_url in candidate_urls:
                    try:
                        async with session.get(
                            probe_url,
                            allow_redirects=(provider != Provider.AWS),
                            ssl=False,
                        ) as resp:
                            body = await resp.text(errors="replace")
                            result.scan_time_ms = int((time.monotonic() - start) * 1000)
                            result.url = probe_url

                            if logger.isEnabledFor(logging.DEBUG):
                                body_snippet = body[:300].replace("\n", " ")
                                logger.debug(
                                    f"[{provider.value}] {name} → {resp.status} "
                                    f"region_hdr={resp.headers.get('x-amz-bucket-region', '')} "
                                    f"body={body_snippet}"
                                )

                            aws_region_hint = resp.headers.get("x-amz-bucket-region", "").strip()
                            is_aws_redirect = (
                                provider == Provider.AWS
                                and (
                                    resp.status in (301, 307, 400)
                                    or "PermanentRedirect" in body
                                    or "AuthorizationHeaderMalformed" in body
                                    or "IncorrectEndpoint" in body
                                )
                            )

                            if resp.status == 200 and cfg["list_marker"] in body:
                                result.status = "open"
                                result.files = self._parse_listing(body, probe_url, name)
                                result.file_count = len(result.files)
                                return result
                            if resp.status == 200:
                                # Website endpoint returned content (bucket is public)
                                result.status = "open"
                                return result
                            if resp.status == 403 or cfg["denied_marker"] in body:
                                result.status = "closed"
                                return result
                            if is_aws_redirect:
                                # Bucket exists but in a different AWS region.
                                result.status = "closed"
                                if aws_region_hint:
                                    result.region = aws_region_hint
                                else:
                                    m = re.search(r'<Endpoint>.*?\.s3[.-]([a-z0-9-]+)\.amazonaws', body)
                                    if not m:
                                        m = re.search(r's3-website[.-]([a-z0-9-]+)\.amazonaws', body)
                                    if m:
                                        result.region = m.group(1)
                                result.url = self._build_url(provider, name, result.region or region)
                                return result
                            if "NoSuchWebsiteConfiguration" in body:
                                # Bucket exists but has no website config — still a discovery.
                                result.status = "closed"
                                return result
                            if resp.status == 404 or cfg["missing_marker"] in body:
                                any_not_found = True
                                continue
                            any_not_found = True
                    except asyncio.TimeoutError:
                        last_error = "timeout"
                    except aiohttp.ClientError as e:
                        last_error = str(e)[:200]

                if last_error and not any_not_found:
                    result.status = "error"
                    result.error = last_error
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

                # Emit progress every 10 checks (or on first check)
                if on_progress and (self.progress.names_checked <= 1 or self.progress.names_checked % 10 == 0):
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


# ═══════════════════════════════════════════════════════════════════
# CLI ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════

def main():
    """CLI entrypoint: python3 -m backend.app.scanners.engine"""
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="CloudScan — Multi-Provider Bucket Discovery Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 -m backend.app.scanners.engine -k backup database credentials
  python3 -m backend.app.scanners.engine -k secret -c acme-corp globex -p aws gcp -n 2000
  python3 -m backend.app.scanners.engine -k terraform .env config -n 5000 --concurrency 100
        """,
    )
    parser.add_argument("-k", "--keywords", nargs="+", default=[], help="Keywords for name generation")
    parser.add_argument("-c", "--companies", nargs="+", default=[], help="Company names for targeted scanning")
    parser.add_argument("-p", "--providers", nargs="+", default=[],
                        choices=["aws", "azure", "gcp", "digitalocean", "alibaba"],
                        help="Providers to scan (default: all)")
    parser.add_argument("-n", "--max-names", type=int, default=500, help="Max candidate names (default: 500)")
    parser.add_argument("-r", "--regions", type=int, default=3, help="Regions per provider (default: 3)")
    parser.add_argument("--concurrency", type=int, default=50, help="Concurrent requests (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-db", action="store_true", help="Don't persist results to database")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if not args.keywords and not args.companies:
        parser.error("At least --keywords or --companies required")

    if aiohttp is None:
        print("ERROR: aiohttp is required for scanning. Install: pip install aiohttp")
        sys.exit(1)

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Resolve providers
    target_providers = [Provider(p) for p in args.providers] if args.providers else list(Provider)

    # DB setup (optional)
    db_store = None
    if not args.no_db:
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from backend.app.models.database import init_db, BucketStore, FileStore
            init_db()
            db_store = (BucketStore, FileStore)
            logger.info("Database connected — results will be persisted")
        except Exception as e:
            logger.warning(f"Database unavailable ({e}) — results will only be printed")

    # Progress display
    open_buckets = []

    def on_progress(progress: ScanProgress):
        pct = (progress.names_checked / progress.names_total * 100) if progress.names_total else 0
        bar = "█" * int(pct / 2.5) + "░" * (40 - int(pct / 2.5))
        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}%  "
            f"checked={progress.names_checked}/{progress.names_total}  "
            f"found={progress.buckets_found}  "
            f"open={progress.buckets_open}  "
            f"files={progress.files_indexed}  "
            f"errors={progress.errors}  "
            f"[{progress.provider}]    "
        )
        sys.stdout.flush()

    def on_result(result: BucketResult):
        if result.status in ("open", "closed", "partial"):
            icon = {"open": "🟢", "closed": "🔴", "partial": "🟡"}.get(result.status, "⚪")
            file_info = f" — {result.file_count} files" if result.file_count else ""
            print(f"\n  {icon} [{result.provider:>12}] {result.name:<40} {result.status.upper()}{file_info}  ({result.scan_time_ms}ms)")

            if result.status == "open":
                open_buckets.append(result)

            # Persist to DB
            if db_store and result.status in ("open", "closed", "partial"):
                try:
                    BStore, FStore = db_store
                    provider_id = PROVIDER_DB_IDS.get(Provider(result.provider), 1)
                    bucket = BStore.upsert(
                        provider_id=provider_id, name=result.name,
                        region=result.region, url=result.url,
                        status=result.status, scan_time_ms=result.scan_time_ms,
                    )
                    if result.status == "open" and result.files:
                        FStore.insert_batch(bucket["id"], result.files)
                except Exception as e:
                    logger.error(f"DB persist error for {result.name}: {e}")

    # Run scan
    print(f"\n☁  CloudScan — Discovery Scan")
    print(f"   Keywords:  {', '.join(args.keywords) if args.keywords else '—'}")
    print(f"   Companies: {', '.join(args.companies) if args.companies else '—'}")
    print(f"   Providers: {', '.join(p.value for p in target_providers)}")
    print(f"   Max names: {args.max_names}")
    print(f"   Concurrency: {args.concurrency}")
    print()

    async def _run():
        scanner = BucketScanner(
            concurrency=args.concurrency,
            timeout=args.timeout,
        )
        try:
            results = await scanner.run_discovery(
                providers=target_providers,
                keywords=args.keywords if args.keywords else None,
                companies=args.companies if args.companies else None,
                max_names=args.max_names,
                regions_per_provider=args.regions,
                on_progress=on_progress,
                on_result=on_result,
            )
            return results, scanner.progress
        finally:
            await scanner.close()

    results, final_progress = asyncio.run(_run())

    # Summary
    print(f"\n\n{'═' * 60}")
    print(f"  Scan Complete")
    print(f"{'═' * 60}")
    print(f"  Names checked:  {final_progress.names_checked}")
    print(f"  Buckets found:  {final_progress.buckets_found}")
    print(f"  Open buckets:   {len(open_buckets)}")
    print(f"  Files indexed:  {sum(r.file_count for r in open_buckets)}")

    if open_buckets:
        print(f"\n  Open Buckets:")
        for b in open_buckets:
            print(f"    🟢 {b.provider}://{b.name} — {b.file_count} files — {b.url}")

    if db_store:
        print(f"\n  ✓ Results saved to database")
    print()


if __name__ == "__main__":
    main()
