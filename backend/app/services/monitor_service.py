"""
Attack Surface Monitoring Service.

Runs scheduled watchlist scans, compares results against previous state,
and generates alerts for:
  - New open buckets discovered
  - Sensitive files exposed (credentials, keys, configs)
  - Bucket status changes (open→closed, closed→open)
  - New files added to monitored buckets
"""
import asyncio
import json
import logging
import threading
import time
import traceback
from datetime import datetime, timedelta
from typing import Callable

from backend.app.models.database import (
    WatchlistStore, AlertStore, MonitoredAssetStore,
    BucketStore, FileStore, ScanJobStore, get_db,
)
from backend.app.scanners.engine import (
    BucketScanner, BucketResult, Provider, PROVIDER_DB_IDS,
    ScanProgress, generate_bucket_names,
)
from backend.app.config import settings

logger = logging.getLogger(__name__)


class MonitoringService:
    """Executes watchlist scans and generates security alerts."""

    def __init__(self, event_callback: Callable = None):
        self._event_cb = event_callback
        self._running = False
        self._thread = None

    def _emit(self, event_type: str, data: dict):
        if self._event_cb:
            try:
                self._event_cb(event_type, data)
            except Exception:
                pass

    async def run_watchlist_scan(self, watchlist: dict) -> dict:
        """Execute a single watchlist scan and generate alerts."""
        wl_id = watchlist["id"]
        user_id = watchlist["user_id"]
        keywords = json.loads(watchlist["keywords"]) if isinstance(watchlist["keywords"], str) else watchlist["keywords"]
        companies = json.loads(watchlist.get("companies", "[]") or "[]")
        providers_raw = json.loads(watchlist.get("providers", "[]") or "[]")

        target_providers = []
        for p in (providers_raw or []):
            try:
                target_providers.append(Provider(p))
            except ValueError:
                pass
        if not target_providers:
            target_providers = list(Provider)

        logger.info(f"[Monitor] Scanning watchlist '{watchlist['name']}' (id={wl_id}) keywords={keywords}")

        scanner = BucketScanner(
            concurrency=settings.SCANNER_CONCURRENCY,
            timeout=settings.SCANNER_TIMEOUT,
        )

        results_summary = {
            "new_buckets": 0, "new_open": 0, "sensitive_files": 0,
            "status_changes": 0, "alerts_created": 0, "names_checked": 0,
        }

        def on_result(result: BucketResult):
            if result.status not in ("open", "closed", "partial"):
                return

            try:
                provider_id = PROVIDER_DB_IDS.get(Provider(result.provider), 1)
                bucket = BucketStore.upsert(
                    provider_id=provider_id, name=result.name,
                    region=result.region, url=result.url,
                    status=result.status, scan_time_ms=result.scan_time_ms,
                )
                bucket_id = bucket["id"]

                if result.status == "open" and result.files:
                    FileStore.insert_batch(bucket_id, result.files)

                # Track in monitored assets
                asset = MonitoredAssetStore.upsert(wl_id, bucket_id, result.status, result.file_count)

                # ── Alert: Status change ──
                prev_status = asset.get("previous_status")
                if prev_status and prev_status != result.status:
                    results_summary["status_changes"] += 1
                    severity = "critical" if result.status == "open" and prev_status == "closed" else "medium"
                    AlertStore.create(
                        watchlist_id=wl_id, user_id=user_id,
                        alert_type="status_change", severity=severity,
                        title=f"Bucket status changed: {result.name}",
                        description=f"{prev_status} → {result.status}",
                        bucket_id=bucket_id,
                        metadata={"from": prev_status, "to": result.status},
                    )
                    results_summary["alerts_created"] += 1

                # ── Alert: New open bucket ──
                elif not prev_status and result.status == "open":
                    results_summary["new_open"] += 1
                    AlertStore.create(
                        watchlist_id=wl_id, user_id=user_id,
                        alert_type="new_bucket", severity="high",
                        title=f"New open bucket discovered: {result.name}",
                        description=f"{result.provider}://{result.name} — {result.file_count} files exposed",
                        bucket_id=bucket_id,
                        metadata={"provider": result.provider, "file_count": result.file_count},
                    )
                    results_summary["alerts_created"] += 1

                # ── Alert: New files in existing bucket ──
                prev_count = asset.get("file_count_prev", 0)
                if prev_count and result.file_count > prev_count:
                    new_files = result.file_count - prev_count
                    AlertStore.create(
                        watchlist_id=wl_id, user_id=user_id,
                        alert_type="new_files", severity="medium",
                        title=f"{new_files} new files in {result.name}",
                        description=f"File count: {prev_count} → {result.file_count}",
                        bucket_id=bucket_id,
                        metadata={"prev": prev_count, "curr": result.file_count},
                    )
                    results_summary["alerts_created"] += 1

                # ── Alert: Sensitive files ──
                if result.status == "open" and result.files:
                    findings = AlertStore.detect_sensitive_files(bucket_id, result.files)
                    for finding in findings:
                        results_summary["sensitive_files"] += 1
                        AlertStore.create(
                            watchlist_id=wl_id, user_id=user_id,
                            alert_type="sensitive_file", severity=finding["severity"],
                            title=finding["title"],
                            description=f"Found in {result.provider}://{result.name}/{finding['file']['filepath']}",
                            bucket_id=bucket_id,
                            metadata={"pattern": finding["pattern"], "file": finding["file"]["filepath"]},
                        )
                        results_summary["alerts_created"] += 1

                results_summary["new_buckets"] += 1

            except Exception as e:
                logger.error(f"[Monitor] Error processing result for {result.name}: {e}")

        def on_progress(progress: ScanProgress):
            results_summary["names_checked"] = progress.names_checked
            self._emit("monitor_progress", {
                "watchlist_id": wl_id,
                "progress": progress.to_dict(),
            })

        try:
            await scanner.run_discovery(
                providers=target_providers,
                keywords=keywords,
                companies=companies if companies else None,
                max_names=min(len(keywords) * 200, 2000),
                regions_per_provider=2,
                on_progress=on_progress,
                on_result=on_result,
            )
        finally:
            await scanner.close()

        WatchlistStore.mark_scanned(wl_id, watchlist.get("scan_interval_hours", 24))

        self._emit("monitor_complete", {
            "watchlist_id": wl_id,
            "summary": results_summary,
        })

        logger.info(f"[Monitor] Watchlist '{watchlist['name']}' complete: "
                     f"{results_summary['new_open']} open, "
                     f"{results_summary['sensitive_files']} sensitive, "
                     f"{results_summary['alerts_created']} alerts")

        return results_summary

    def scan_watchlist_async(self, watchlist: dict):
        """Run a watchlist scan in a background thread."""
        def _run():
            try:
                asyncio.run(self.run_watchlist_scan(watchlist))
            except Exception as e:
                logger.error(f"[Monitor] Watchlist scan crashed: {e}\n{traceback.format_exc()}")

        t = threading.Thread(target=_run, daemon=True, name=f"monitor-{watchlist['id']}")
        t.start()
        return t

    def start_scheduler(self, check_interval_seconds: int = 300):
        """Start background scheduler that checks for due watchlists."""
        if self._running:
            return

        self._running = True

        def _scheduler_loop():
            logger.info("[Monitor] Scheduler started")
            while self._running:
                try:
                    due = WatchlistStore.list_due()
                    for wl in due:
                        logger.info(f"[Monitor] Watchlist '{wl['name']}' is due, starting scan...")
                        self.scan_watchlist_async(wl)
                except Exception as e:
                    logger.error(f"[Monitor] Scheduler error: {e}")
                time.sleep(check_interval_seconds)

        self._thread = threading.Thread(target=_scheduler_loop, daemon=True, name="monitor-scheduler")
        self._thread.start()
        logger.info(f"[Monitor] Scheduler running, checking every {check_interval_seconds}s")

    def stop_scheduler(self):
        self._running = False
