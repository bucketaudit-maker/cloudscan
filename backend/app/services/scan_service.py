"""
Scan Service — Orchestrates discovery scans with DB persistence and real-time events.
Bridges the scanner engine with the database and WebSocket layer.
"""
import asyncio
import json
import logging
import threading
from datetime import datetime
from typing import Callable, Optional

from backend.app.models.database import BucketStore, FileStore, ScanJobStore, get_db
from backend.app.scanners.engine import (
    BucketScanner, BucketResult, Provider, PROVIDER_DB_IDS,
    ScanProgress, enumerate_bucket_deep,
)
from backend.app.config import settings

logger = logging.getLogger(__name__)


class ScanService:
    """
    Manages scan lifecycle:
      1. Create scan job in DB
      2. Run async scanner with progress callbacks
      3. Persist results to DB in real-time
      4. Stream progress via callback (for WebSocket/SSE)
    """

    def __init__(self, event_callback: Callable = None):
        """
        Args:
            event_callback: Called with (event_type, data) for real-time streaming.
                            event_type: 'progress', 'bucket_found', 'scan_complete', 'error'
        """
        self._event_cb = event_callback
        self._active_scans: dict[int, asyncio.Task] = {}

    def _emit(self, event_type: str, data: dict):
        if self._event_cb:
            try:
                self._event_cb(event_type, data)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    async def start_discovery(
        self,
        keywords: list[str] = None,
        companies: list[str] = None,
        providers: list[str] = None,
        max_names: int = 1000,
        regions_per_provider: int = 3,
        created_by: int = None,
    ) -> dict:
        """
        Start a discovery scan. Returns the job record immediately.
        The scan runs asynchronously.
        """
        # Resolve providers
        target_providers = []
        if providers:
            for p in providers:
                try:
                    target_providers.append(Provider(p))
                except ValueError:
                    logger.warning(f"Unknown provider: {p}")
        else:
            target_providers = list(Provider)

        # Create job record
        config = {
            "keywords": keywords or [],
            "companies": companies or [],
            "providers": [p.value for p in target_providers],
            "max_names": max_names,
            "regions_per_provider": regions_per_provider,
        }
        job = ScanJobStore.create("discovery", config, created_by)
        job_id = job["id"]

        # Run scan in background
        async def _run():
            scanner = BucketScanner(
                concurrency=settings.SCANNER_CONCURRENCY,
                timeout=settings.SCANNER_TIMEOUT,
                user_agent=settings.SCANNER_USER_AGENT,
            )

            ScanJobStore.update(job_id,
                status="running",
                started_at=datetime.utcnow().isoformat(),
            )
            self._emit("scan_started", {"job_id": job_id, "config": config})

            errors_list = []

            def on_progress(progress: ScanProgress):
                progress.job_id = job_id
                self._emit("progress", progress.to_dict())
                # Update job progress periodically
                ScanJobStore.update(job_id,
                    progress=json.dumps(progress.to_dict()),
                    names_checked=progress.names_checked,
                    buckets_found=progress.buckets_found,
                    buckets_open=progress.buckets_open,
                    files_indexed=progress.files_indexed,
                )

            def on_result(result: BucketResult):
                try:
                    # Persist to DB
                    provider_id = PROVIDER_DB_IDS.get(Provider(result.provider), 1)
                    bucket = BucketStore.upsert(
                        provider_id=provider_id,
                        name=result.name,
                        region=result.region,
                        url=result.url,
                        status=result.status,
                        scan_time_ms=result.scan_time_ms,
                    )

                    if result.status == "open" and result.files:
                        count = FileStore.insert_batch(bucket["id"], result.files)
                        logger.info(f"[OPEN] {result.provider}://{result.name} — {count} files indexed")

                    # Emit real-time event
                    self._emit("bucket_found", {
                        "job_id": job_id,
                        "bucket": {
                            "id": bucket.get("id"),
                            "provider": result.provider,
                            "name": result.name,
                            "region": result.region,
                            "url": result.url,
                            "status": result.status,
                            "file_count": result.file_count,
                            "scan_time_ms": result.scan_time_ms,
                        },
                    })
                except Exception as e:
                    logger.error(f"Error persisting result for {result.name}: {e}")
                    errors_list.append(f"{result.name}: {str(e)[:100]}")

            try:
                results = await scanner.run_discovery(
                    providers=target_providers,
                    keywords=keywords,
                    companies=companies,
                    max_names=max_names,
                    regions_per_provider=regions_per_provider,
                    on_progress=on_progress,
                    on_result=on_result,
                )

                ScanJobStore.update(job_id,
                    status="completed",
                    completed_at=datetime.utcnow().isoformat(),
                    buckets_found=scanner.progress.buckets_found,
                    buckets_open=scanner.progress.buckets_open,
                    files_indexed=scanner.progress.files_indexed,
                    names_checked=scanner.progress.names_checked,
                    errors=json.dumps(errors_list[-50:]) if errors_list else None,
                )

                self._emit("scan_complete", {
                    "job_id": job_id,
                    "stats": scanner.progress.to_dict(),
                })

            except Exception as e:
                logger.error(f"Scan {job_id} failed: {e}")
                ScanJobStore.update(job_id,
                    status="failed",
                    completed_at=datetime.utcnow().isoformat(),
                    errors=json.dumps([str(e)]),
                )
                self._emit("error", {"job_id": job_id, "error": str(e)})

            finally:
                await scanner.close()
                self._active_scans.pop(job_id, None)

        # Schedule in current event loop or create new one
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(_run())
        except RuntimeError:
            # No running loop — start one in a thread
            def _thread_run():
                asyncio.run(_run())
            t = threading.Thread(target=_thread_run, daemon=True)
            t.start()
            task = None

        if task:
            self._active_scans[job_id] = task

        return ScanJobStore.get(job_id)

    async def cancel_scan(self, job_id: int) -> bool:
        """Cancel a running scan."""
        task = self._active_scans.get(job_id)
        if task and not task.done():
            task.cancel()
            ScanJobStore.update(job_id,
                status="cancelled",
                completed_at=datetime.utcnow().isoformat(),
            )
            self._emit("scan_cancelled", {"job_id": job_id})
            return True
        return False

    def get_active_scans(self) -> list[int]:
        """Return IDs of currently running scans."""
        return [jid for jid, task in self._active_scans.items() if not task.done()]
