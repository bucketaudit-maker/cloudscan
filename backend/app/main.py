"""
BucketAudit API Server — Production Flask application factory.

Usage:
    python -m backend.app.main          # Development server
    gunicorn backend.app.main:app       # Production server
"""
import logging
import os
import sys

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Load .env from repo root before importing settings
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
load_dotenv(os.path.join(_repo_root, ".env"))

from backend.app.config import settings
from backend.app.models.database import init_db
from backend.app.api.routes import api


def create_app() -> Flask:
    """Flask application factory."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.SECRET_KEY

    # CORS: production never allows '*'; debug adds '*' for dev convenience
    CORS(app, origins=settings.cors_origins)

    # Logging
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Initialize database only when explicitly enabled.
    if settings.RUN_DB_MIGRATIONS_ON_STARTUP:
        init_db()
    else:
        logging.getLogger(__name__).info("Skipping DB migration on API startup (RUN_DB_MIGRATIONS_ON_STARTUP=false)")
    logging.getLogger(__name__).info(f"BucketAudit API starting (env={settings.APP_ENV})")

    # Initialize AI providers
    if settings.AI_ENABLED:
        from backend.app.services.providers.registry import init_default_provider
        init_default_provider()

    # Register blueprints
    app.register_blueprint(api)

    # Register Sprint 7 features blueprint under the same prefix
    from backend.app.api.features_routes import features_api
    app.register_blueprint(features_api, url_prefix="/api/v1")

    # Start monitoring scheduler only in scheduler role, not in every API worker.
    if settings.ENABLE_MONITOR_SCHEDULER:
        from backend.app.api.routes import monitor_service
        monitor_service.start_scheduler(check_interval_seconds=settings.MONITOR_SCHEDULER_INTERVAL_SECONDS)
        logging.getLogger(__name__).info(
            "Monitor scheduler enabled in API process (interval=%ss)",
            settings.MONITOR_SCHEDULER_INTERVAL_SECONDS,
        )
    else:
        logging.getLogger(__name__).info("Monitor scheduler disabled in API process (ENABLE_MONITOR_SCHEDULER=false)")

    # Start scan scheduler to auto-execute due scan schedules.
    if settings.ENABLE_SCAN_SCHEDULER:
        from backend.app.api.routes import scan_service
        from backend.app.services.scan_scheduler import ScanScheduler
        scan_scheduler = ScanScheduler(scan_service)
        scan_scheduler.start(check_interval_seconds=settings.SCAN_SCHEDULER_INTERVAL_SECONDS)
        logging.getLogger(__name__).info(
            "Scan scheduler enabled (interval=%ss)",
            settings.SCAN_SCHEDULER_INTERVAL_SECONDS,
        )
    else:
        logging.getLogger(__name__).info("Scan scheduler disabled (ENABLE_SCAN_SCHEDULER=false)")

    # Global error handlers — prevent stack trace leaks in production
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found", "status": 404}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed", "status": 405}), 405

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"error": "Rate limit exceeded. Please try again later.", "status": 429}), 429

    @app.errorhandler(500)
    def internal_error(e):
        logging.getLogger(__name__).error("Unhandled 500 error: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "status": 500}), 500

    @app.errorhandler(Exception)
    def handle_unexpected(e):
        if isinstance(e, HTTPException):
            return jsonify({"error": e.description, "status": e.code}), e.code
        logging.getLogger(__name__).error("Unexpected error: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "status": 500}), 500

    # Health check at root
    @app.route("/")
    def root():
        return {"name": "BucketAudit API", "version": "1.0.0", "docs": "/api/v1/docs"}

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    app.run(
        host=settings.API_HOST,
        port=settings.API_PORT,
        debug=settings.DEBUG,
        threaded=True,
        use_reloader=False,  # Reloader spawns child process — breaks SSE + scan threads
    )
