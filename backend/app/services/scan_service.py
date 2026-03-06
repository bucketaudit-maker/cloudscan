"""
Scan Service — Orchestrates discovery scans with DB persistence and real-time events.
"""
import asyncio
import json
import logging
import threading
import traceback
import sys
from datetime import datetime
from typing import Callable

from backend.app.models.database import BucketStore, FileStore, ScanJobStore
from backend.app.scanners.engine import (
    BucketScanner, BucketResult, Provider, PROVIDER_DB_IDS,
    ScanProgress,
)
from backend.app.config import settings

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, event_callback: Callable = None):
        self._event_cb = event_callback
        self._active_threads: dict[int, threading.Thread] = {}

    def _emit(self, event_type: str, data: dict):
        if self._event_cb:
            try:
                self._event_cb(event_type, data)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def start_discovery(self, keywords=None, companies=None, providers=None,
                        max_names=1000, regions_per_provider=3, created_by=None) -> dict:
        target_providers = []
        if providers:
            for p in providers:
                try:
                    target_providers.append(Provider(p))
                except ValueError:
                    logger.warning(f"Unknown provider: {p}")
        if not target_providers:
            target_providers = list(Provider)

        config = {
            "keywords": keywords or [], "companies": companies or [],
            "providers": [p.value for p in target_providers],
            "max_names": max_names, "regions_per_provider": regions_per_provider,
        }
        job = ScanJobStore.create("discovery", config, created_by)
        job_id = job["id"]
        logger.info(f"Scan job {job_id} created: keywords={keywords}, providers={[p.value for p in target_providers]}")

        def _thread_target():
            logger.info(f"[Thread {job_id}] Starting asyncio.run...")
            try:
                asyncio.run(self._run_scan(
                    job_id=job_id, config=config,
                    target_providers=target_providers,
                    keywords=keywords, companies=companies,
                    max_names=max_names,
                    regions_per_provider=regions_per_provider,
                ))
                logger.info(f"[Thread {job_id}] asyncio.run completed normally")
            except BaseException as e:
                # Catch EVERYTHING — including SystemExit, KeyboardInterrupt
                err_msg = f"{type(e).__name__}: {e}"
                tb = traceback.format_exc()
                logger.error(f"[Thread {job_id}] CRASHED: {err_msg}\n{tb}")
                # Print to stderr as well in case logger is broken
                print(f"[SCAN THREAD {job_id} CRASHED] {err_msg}\n{tb}", file=sys.stderr, flush=True)
                try:
                    ScanJobStore.update(job_id, status="failed",
                        completed_at=datetime.utcnow().isoformat(),
                        errors=json.dumps([err_msg, tb[-500:]]))
                except Exception:
                    pass
            finally:
                self._active_threads.pop(job_id, None)
                logger.info(f"[Thread {job_id}] Thread exiting")

        t = threading.Thread(target=_thread_target, daemon=True, name=f"scan-{job_id}")
        t.start()
        self._active_threads[job_id] = t
        logger.info(f"Scan thread {job_id} launched (thread={t.name}, alive={t.is_alive()})")
        return ScanJobStore.get(job_id)

    async def _run_scan(self, job_id, config, target_providers, keywords=None,
                        companies=None, max_names=1000, regions_per_provider=3):
        logger.info(f"[Scan {job_id}] _run_scan starting, creating BucketScanner...")

        scanner = BucketScanner(
            concurrency=settings.SCANNER_CONCURRENCY,
            timeout=settings.SCANNER_TIMEOUT,
            user_agent=settings.SCANNER_USER_AGENT,
        )
        logger.info(f"[Scan {job_id}] BucketScanner created, updating job to running...")

        ScanJobStore.update(job_id, status="running",
            started_at=datetime.utcnow().isoformat())
        self._emit("scan_started", {"job_id": job_id, "config": config})
        logger.info(f"[Scan {job_id}] Job marked running, starting discovery...")

        errors_list = []

        def on_progress(progress: ScanProgress):
            progress.job_id = job_id
            self._emit("progress", progress.to_dict())
            try:
                ScanJobStore.update(job_id,
                    progress=json.dumps(progress.to_dict()),
                    names_checked=progress.names_checked,
                    buckets_found=progress.buckets_found,
                    buckets_open=progress.buckets_open,
                    files_indexed=progress.files_indexed)
            except Exception as e:
                logger.warning(f"Progress DB update error: {e}")

        def on_result(result: BucketResult):
            try:
                provider_id = PROVIDER_DB_IDS.get(Provider(result.provider), 1)
                bucket = BucketStore.upsert(
                    provider_id=provider_id, name=result.name,
                    region=result.region, url=result.url,
                    status=result.status, scan_time_ms=result.scan_time_ms)
                if result.status == "open" and result.files:
                    count = FileStore.insert_batch(bucket["id"], result.files)
                    logger.info(f"[OPEN] {result.provider}://{result.name} — {count} files")
                self._emit("bucket_found", {
                    "job_id": job_id,
                    "bucket": {
                        "id": bucket.get("id"), "provider": result.provider,
                        "name": result.name, "region": result.region,
                        "url": result.url, "status": result.status,
                        "file_count": result.file_count,
                        "scan_time_ms": result.scan_time_ms,
                    }})
            except Exception as e:
                logger.error(f"Error persisting {result.name}: {e}")
                errors_list.append(f"{result.name}: {str(e)[:100]}")

        try:
            logger.info(f"[Scan {job_id}] Calling scanner.run_discovery...")
            await scanner.run_discovery(
                providers=target_providers, keywords=keywords,
                companies=companies, max_names=max_names,
                regions_per_provider=regions_per_provider,
                on_progress=on_progress, on_result=on_result)

            ScanJobStore.update(job_id,
                status="completed",
                completed_at=datetime.utcnow().isoformat(),
                buckets_found=scanner.progress.buckets_found,
                buckets_open=scanner.progress.buckets_open,
                files_indexed=scanner.progress.files_indexed,
                names_checked=scanner.progress.names_checked,
                errors=json.dumps(errors_list[-50:]) if errors_list else None)

            self._emit("scan_complete", {
                "job_id": job_id, "stats": scanner.progress.to_dict()})
            logger.info(f"[Scan {job_id}] COMPLETE: {scanner.progress.buckets_open} open, {scanner.progress.files_indexed} files")

        except Exception as e:
            logger.error(f"[Scan {job_id}] FAILED in run_discovery: {e}\n{traceback.format_exc()}")
            ScanJobStore.update(job_id, status="failed",
                completed_at=datetime.utcnow().isoformat(),
                errors=json.dumps([str(e)]))
            self._emit("error", {"job_id": job_id, "error": str(e)})
        finally:
            await scanner.close()

    def cancel_scan(self, job_id: int) -> bool:
        t = self._active_threads.get(job_id)
        if t and t.is_alive():
            ScanJobStore.update(job_id, status="cancelled",
                completed_at=datetime.utcnow().isoformat())
            self._emit("scan_cancelled", {"job_id": job_id})
            return True
        return False

    def get_active_scans(self) -> list[int]:
        return [jid for jid, t in self._active_threads.items() if t.is_alive()]
