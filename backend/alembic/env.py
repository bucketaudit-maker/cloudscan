"""
Alembic environment: use DATABASE_URL from app config, run raw SQL migrations.
"""
import os
import sys

# Add project root so backend.app.config is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Add repo root (parent of backend)
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, repo_root)

from logging.config import fileConfig
from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.engine import Connection

# Import app settings for DATABASE_URL
os.environ.setdefault("APP_ENV", "development")
from backend.app.config import settings

config = context.config
if config.config_file_name is not None:
    # Allow a minimal alembic.ini without Python logging sections.
    try:
        ini_cfg = config.file_config
        has_logging_cfg = (
            ini_cfg.has_section("loggers")
            and ini_cfg.has_section("handlers")
            and ini_cfg.has_section("formatters")
        )
    except Exception:
        has_logging_cfg = False
    if has_logging_cfg:
        fileConfig(config.config_file_name)
target_metadata = None


def get_url() -> str:
    url = settings.DATABASE_URL
    if not url.strip().lower().startswith("postgresql"):
        raise ValueError("Alembic migrations require PostgreSQL. Set DATABASE_URL to a postgresql:// URL.")
    return url


def run_migrations_offline() -> None:
    context.configure(url=get_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(get_url())
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
