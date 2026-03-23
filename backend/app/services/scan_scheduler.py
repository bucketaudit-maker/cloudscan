"""
Scan Scheduler — Background thread that auto-executes due scan schedules.

Checks ScanScheduleStore.list_due() on a configurable interval and triggers
scans via ScanService for any schedules whose next_run_at has passed.
"""
import json
import logging
import threading
import time
from typing import Callable

from backend.app.models.database import ScanScheduleStore
from backend.app.services.scan_service import ScanService
from backend.app.config import settings

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Periodically checks for due scan schedules and runs them."""

    def __init__(self, scan_service: ScanService):
        self._scan_service = scan_service
        self._running = False
        self._thread = None

    def start(self, check_interval_seconds: int = 60):
        if self._running:
            return

        self._running = True

        def _loop():
            logger.info("[ScanScheduler] Started, checking every %ss", check_interval_seconds)
            while self._running:
                try:
                    due = ScanScheduleStore.list_due()
                    for schedule in due:
                        self._execute_schedule(schedule)
                except Exception as e:
                    logger.error("[ScanScheduler] Error checking due schedules: %s", e)
                time.sleep(check_interval_seconds)

        self._thread = threading.Thread(target=_loop, daemon=True, name="scan-scheduler")
        self._thread.start()

    def _execute_schedule(self, schedule: dict):
        sid = schedule["id"]
        name = schedule.get("name", f"schedule-{sid}")
        try:
            keywords = json.loads(schedule["keywords"]) if isinstance(schedule["keywords"], str) else schedule["keywords"]
            companies = json.loads(schedule.get("companies", "[]") or "[]") if isinstance(schedule.get("companies", "[]"), str) else schedule.get("companies", [])
            providers = json.loads(schedule.get("providers", "[]") or "[]") if isinstance(schedule.get("providers", "[]"), str) else schedule.get("providers", [])

            logger.info("[ScanScheduler] Running schedule '%s' (id=%s) keywords=%s", name, sid, keywords)

            job = self._scan_service.start_discovery(
                keywords=keywords,
                companies=companies if companies else None,
                providers=providers if providers else None,
                created_by=schedule.get("user_id"),
            )

            ScanScheduleStore.mark_run(sid, job.get("id"), schedule.get("frequency", "daily"))
            logger.info("[ScanScheduler] Schedule '%s' launched job %s, next run updated", name, job.get("id"))

        except Exception as e:
            logger.error("[ScanScheduler] Failed to execute schedule '%s' (id=%s): %s", name, sid, e)

    def stop(self):
        self._running = False
