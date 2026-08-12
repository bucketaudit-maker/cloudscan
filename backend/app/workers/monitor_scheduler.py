"""
Dedicated scheduler worker process for watchlists and recurring discovery scans.

Run:
    backend/venv/bin/python3 -m backend.app.workers.monitor_scheduler
"""
import logging
import signal
import sys
import threading
from pathlib import Path

from dotenv import load_dotenv

# Ensure project root is on path
repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))
load_dotenv(repo_root / ".env")

from backend.app.config import settings
from backend.app.models.database import get_db
from backend.app.services.monitor_service import MonitoringService
from backend.app.services.scan_scheduler import ScanScheduler
from backend.app.services.scan_service import ScanService


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger(__name__)

    # Migrations are an explicit deployment step; workers only verify connectivity.
    with get_db() as db:
        db.execute("SELECT 1")
    logger.info("Database connection verified")

    monitor = MonitoringService()
    scan_scheduler = ScanScheduler(ScanService())

    if settings.ENABLE_MONITOR_SCHEDULER:
        monitor.start_scheduler(
            check_interval_seconds=settings.MONITOR_SCHEDULER_INTERVAL_SECONDS
        )
        logger.info(
            "Monitor scheduler started (interval=%ss)",
            settings.MONITOR_SCHEDULER_INTERVAL_SECONDS,
        )

    if settings.ENABLE_SCAN_SCHEDULER:
        scan_scheduler.start(
            check_interval_seconds=settings.SCAN_SCHEDULER_INTERVAL_SECONDS
        )
        logger.info(
            "Recurring scan scheduler started (interval=%ss)",
            settings.SCAN_SCHEDULER_INTERVAL_SECONDS,
        )

    if not settings.ENABLE_MONITOR_SCHEDULER and not settings.ENABLE_SCAN_SCHEDULER:
        raise RuntimeError(
            "Scheduler worker has no enabled schedulers. Set ENABLE_MONITOR_SCHEDULER "
            "or ENABLE_SCAN_SCHEDULER to true."
        )

    stop_event = threading.Event()

    def _stop(signum, _frame):
        logger.info("Received signal %s; stopping scheduler worker", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    try:
        stop_event.wait()
    finally:
        logger.info("Stopping scheduler worker...")
        monitor.stop_scheduler()
        scan_scheduler.stop()


if __name__ == "__main__":
    main()
