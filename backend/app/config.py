import json
import os
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "SurfaceWatch API"
    environment: Literal["development", "test", "production"] = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"

    database_url: str = "sqlite:///./surfacewatch.db"
    redis_url: str = "redis://redis:6379/0"

    secret_key: str = Field(
        default="change-me-in-production",
        min_length=16,
        description="JWT signing secret. Override in production.",
    )
    access_token_expire_minutes: int = 60 * 8
    algorithm: str = "HS256"

    cors_origins: list[str] = ["http://localhost:3000"]
    allow_internal_targets: bool = False
    scan_timeout_seconds: float = 3.0
    discovery_timeout_seconds: float = 10.0
    scan_concurrency: int = 5
    inline_scan_runner: bool = True
    max_discovered_assets: int = 250
    max_scan_duration_seconds: int = 600
    aggressive_max_discovered_assets: int = 500
    default_ports: list[int] = [
        80,
        443,
        8080,
        8443,
        3000,
        5000,
        8000,
        5432,
        3306,
        6379,
        9200,
        22,
        21,
        25,
    ]
    aggressive_ports: list[int] = [
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        389,
        443,
        445,
        465,
        587,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        2376,
        3000,
        3306,
        5000,
        5432,
        5601,
        5900,
        5984,
        6379,
        8000,
        8080,
        8443,
        9000,
        9200,
        9300,
        11211,
        27017,
        27018,
    ]


def _validate_settings(settings: Settings) -> None:
    if settings.environment != "production":
        return

    errors: list[str] = []
    if settings.debug:
        errors.append("DEBUG must be false")
    if settings.secret_key in {"change-me-in-production", "change-this-to-a-long-random-secret"} or len(settings.secret_key) < 32:
        errors.append("SECRET_KEY must be a long random value")
    if settings.database_url.startswith("sqlite"):
        errors.append("DATABASE_URL must not use SQLite")
    if settings.allow_internal_targets:
        errors.append("ALLOW_INTERNAL_TARGETS must be false")
    if "*" in settings.cors_origins or any("localhost" in origin or "127.0.0.1" in origin for origin in settings.cors_origins):
        errors.append("CORS_ORIGINS must contain production origins only")

    if errors:
        raise RuntimeError(f"Invalid production configuration: {'; '.join(errors)}")


@lru_cache
def get_settings() -> Settings:
    env_file = ".env"
    if os.path.exists(env_file):
        with open(env_file, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    continue
                key, value = stripped.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())

    cors_raw = os.getenv("CORS_ORIGINS")
    cors_origins = ["http://localhost:3000"]
    if cors_raw:
        try:
            parsed = json.loads(cors_raw)
            cors_origins = parsed if isinstance(parsed, list) else [str(parsed)]
        except json.JSONDecodeError:
            cors_origins = [item.strip() for item in cors_raw.split(",") if item.strip()]

    ports_raw = os.getenv("DEFAULT_PORTS")
    default_ports = Settings().default_ports
    if ports_raw:
        default_ports = [int(item.strip()) for item in ports_raw.split(",") if item.strip()]

    aggressive_ports_raw = os.getenv("AGGRESSIVE_PORTS")
    aggressive_ports = Settings().aggressive_ports
    if aggressive_ports_raw:
        aggressive_ports = [int(item.strip()) for item in aggressive_ports_raw.split(",") if item.strip()]

    settings = Settings(
        app_name=os.getenv("APP_NAME", "SurfaceWatch API"),
        environment=os.getenv("ENVIRONMENT", "development"),
        debug=os.getenv("DEBUG", "false").lower() == "true",
        api_prefix=os.getenv("API_PREFIX", "/api/v1"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./surfacewatch.db"),
        redis_url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
        secret_key=os.getenv("SECRET_KEY", "change-me-in-production"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 8))),
        algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        cors_origins=cors_origins,
        allow_internal_targets=os.getenv("ALLOW_INTERNAL_TARGETS", "false").lower() == "true",
        scan_timeout_seconds=float(os.getenv("SCAN_TIMEOUT_SECONDS", "3.0")),
        discovery_timeout_seconds=float(os.getenv("DISCOVERY_TIMEOUT_SECONDS", "10.0")),
        scan_concurrency=int(os.getenv("SCAN_CONCURRENCY", "5")),
        inline_scan_runner=os.getenv("INLINE_SCAN_RUNNER", "true").lower() == "true",
        max_discovered_assets=int(os.getenv("MAX_DISCOVERED_ASSETS", "250")),
        max_scan_duration_seconds=int(os.getenv("MAX_SCAN_DURATION_SECONDS", "600")),
        aggressive_max_discovered_assets=int(os.getenv("AGGRESSIVE_MAX_DISCOVERED_ASSETS", "500")),
        default_ports=default_ports,
        aggressive_ports=aggressive_ports,
    )
    _validate_settings(settings)
    return settings
