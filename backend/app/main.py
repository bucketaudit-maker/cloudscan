"""
CloudScan API Server — Production Flask application factory.

Usage:
    python -m backend.app.main          # Development server
    gunicorn backend.app.main:app       # Production server
"""
import logging
import os
import sys

from flask import Flask
from flask_cors import CORS

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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

    # Initialize database
    init_db()
    logging.getLogger(__name__).info(f"CloudScan API starting (env={settings.APP_ENV})")

    # Register blueprints
    app.register_blueprint(api)

    # Start monitoring scheduler
    from backend.app.api.routes import monitor_service
    monitor_service.start_scheduler(check_interval_seconds=300)

    # Health check at root
    @app.route("/")
    def root():
        return {"name": "CloudScan API", "version": "1.0.0", "docs": "/api/v1/health"}

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
