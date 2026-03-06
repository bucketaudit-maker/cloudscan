"""
Centralized configuration loaded from environment variables.
Uses pydantic-settings for validation and defaults.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Production will reject this value for SECRET_KEY
DEV_SECRET_KEY = "dev-secret-change-in-production"


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int = 0) -> int:
    return int(os.environ.get(key, str(default)))


def _env_bool(key: str, default: bool = False) -> bool:
    return os.environ.get(key, str(default)).lower() in ("true", "1", "yes")


def _env_list(key: str, default: str = "") -> list[str]:
    val = os.environ.get(key, default)
    return [s.strip() for s in val.split(",") if s.strip()]


@dataclass
class Settings:
    # App
    APP_ENV: str = field(default_factory=lambda: _env("APP_ENV", "development"))
    SECRET_KEY: str = field(default_factory=lambda: _env("SECRET_KEY", DEV_SECRET_KEY))
    DEBUG: bool = field(default_factory=lambda: _env_bool("DEBUG", True))

    def __post_init__(self) -> None:
        """Enforce production security: require SECRET_KEY, force DEBUG=False, no wildcard CORS."""
        if self.APP_ENV != "production":
            return
        if self.SECRET_KEY == DEV_SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ValueError(
                "Production requires SECRET_KEY to be set to a secure random value "
                "(at least 32 characters). Set SECRET_KEY in the environment."
            )
        self.DEBUG = False

    # Database (PostgreSQL default for local and production; SQLite only for tests)
    DATABASE_URL: str = field(default_factory=lambda: _env("DATABASE_URL", "postgresql://cloudscan:cloudscan@localhost:5432/cloudscan"))
    REDIS_URL: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))

    # Scanner
    SCANNER_CONCURRENCY: int = field(default_factory=lambda: _env_int("SCANNER_CONCURRENCY", 50))
    SCANNER_TIMEOUT: int = field(default_factory=lambda: _env_int("SCANNER_TIMEOUT", 10))
    SCANNER_USER_AGENT: str = field(default_factory=lambda: _env("SCANNER_USER_AGENT", "CloudScan/1.0 (Security Research)"))
    SCANNER_MAX_FILES: int = field(default_factory=lambda: _env_int("SCANNER_MAX_FILES_PER_BUCKET", 100000))
    RUN_DB_MIGRATIONS_ON_STARTUP: bool = field(default_factory=lambda: _env_bool("RUN_DB_MIGRATIONS_ON_STARTUP", True))
    ENABLE_MONITOR_SCHEDULER: bool = field(default_factory=lambda: _env_bool("ENABLE_MONITOR_SCHEDULER", False))
    MONITOR_SCHEDULER_INTERVAL_SECONDS: int = field(default_factory=lambda: _env_int("MONITOR_SCHEDULER_INTERVAL_SECONDS", 300))

    # API
    API_HOST: str = field(default_factory=lambda: _env("API_HOST", "0.0.0.0"))
    API_PORT: int = field(default_factory=lambda: _env_int("API_PORT", 8000))
    CORS_ORIGINS: list = field(default_factory=lambda: _env_list("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"))

    # Rate limits
    RATE_LIMIT_FREE: int = field(default_factory=lambda: _env_int("RATE_LIMIT_FREE", 100))
    RATE_LIMIT_PREMIUM: int = field(default_factory=lambda: _env_int("RATE_LIMIT_PREMIUM", 5000))
    RATE_LIMIT_ENTERPRISE: int = field(default_factory=lambda: _env_int("RATE_LIMIT_ENTERPRISE", 50000))

    # JWT
    JWT_EXPIRATION_HOURS: int = field(default_factory=lambda: _env_int("JWT_EXPIRATION_HOURS", 24))

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"

    @property
    def is_postgres(self) -> bool:
        return self.DATABASE_URL.strip().lower().startswith("postgresql")

    @property
    def db_path(self) -> str:
        """Extract SQLite path from DATABASE_URL."""
        if self.DATABASE_URL.startswith("sqlite:///"):
            return self.DATABASE_URL.replace("sqlite:///", "")
        return str(BASE_DIR / "data" / "cloudscan.db")

    @property
    def rate_limits(self) -> dict:
        return {
            "free": self.RATE_LIMIT_FREE,
            "premium": self.RATE_LIMIT_PREMIUM,
            "enterprise": self.RATE_LIMIT_ENTERPRISE,
        }

    @property
    def cors_origins(self) -> list[str]:
        """CORS origins: in production never include '*'; in debug allow '*'."""
        if self.is_production:
            return [o for o in self.CORS_ORIGINS if o and o != "*"]
        if self.DEBUG:
            return self.CORS_ORIGINS + ["*"]
        return self.CORS_ORIGINS


settings = Settings()
