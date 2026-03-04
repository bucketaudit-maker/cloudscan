"""
Centralized configuration loaded from environment variables.
Uses pydantic-settings for validation and defaults.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


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
    SECRET_KEY: str = field(default_factory=lambda: _env("SECRET_KEY", "dev-secret-change-in-production"))
    DEBUG: bool = field(default_factory=lambda: _env_bool("DEBUG", True))

    # Database
    DATABASE_URL: str = field(default_factory=lambda: _env("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'cloudscan.db'}"))
    REDIS_URL: str = field(default_factory=lambda: _env("REDIS_URL", "redis://localhost:6379/0"))

    # Scanner
    SCANNER_CONCURRENCY: int = field(default_factory=lambda: _env_int("SCANNER_CONCURRENCY", 50))
    SCANNER_TIMEOUT: int = field(default_factory=lambda: _env_int("SCANNER_TIMEOUT", 10))
    SCANNER_USER_AGENT: str = field(default_factory=lambda: _env("SCANNER_USER_AGENT", "CloudScan/1.0 (Security Research)"))
    SCANNER_MAX_FILES: int = field(default_factory=lambda: _env_int("SCANNER_MAX_FILES_PER_BUCKET", 100000))

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


settings = Settings()
