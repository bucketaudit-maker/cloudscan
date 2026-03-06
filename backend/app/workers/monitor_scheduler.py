"""
Dedicated monitoring scheduler worker process.

Run:
    python -m backend.app.workers.monitor_scheduler
"""
import logging
import os
import sys
import time

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

from backend.app.config import settings
from backend.app.models.database import init_db
from backend.app.services.monitor_service import MonitoringService


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if settings.DEBUG else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger(__name__)

    if settings.RUN_DB_MIGRATIONS_ON_STARTUP:
        init_db()
    else:
        logger.info("Skipping DB migration on monitor worker startup (RUN_DB_MIGRATIONS_ON_STARTUP=false)")

    monitor = MonitoringService()
    interval = settings.MONITOR_SCHEDULER_INTERVAL_SECONDS
    monitor.start_scheduler(check_interval_seconds=interval)
    logger.info("Monitor scheduler worker started (interval=%ss)", interval)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Stopping monitor scheduler worker...")
        monitor.stop_scheduler()


if __name__ == "__main__":
    main()

