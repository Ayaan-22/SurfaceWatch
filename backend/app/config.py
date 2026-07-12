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
        default="development-only-change-me-32-bytes",
        min_length=16,
        description="JWT signing secret. Override in production.",
    )
    access_token_expire_minutes: int = 60 * 8
    algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"

    cors_origins: list[str] = ["http://localhost:3000"]
    allow_internal_targets: bool = False
    scan_timeout_seconds: float = Field(default=3.0, gt=0, le=30)
    discovery_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    scan_concurrency: int = Field(default=5, ge=1, le=50)
    port_scan_concurrency: int = Field(default=20, ge=1, le=100)
    asset_timeout_seconds: int = Field(default=45, ge=10, le=600)
    aggressive_asset_timeout_seconds: int = Field(default=120, ge=30, le=900)
    max_http_body_bytes: int = Field(default=65536, ge=4096, le=1048576)
    max_exposure_endpoints: int = Field(default=12, ge=1, le=50)
    inline_scan_runner: bool = True
    max_discovered_assets: int = Field(default=250, ge=1, le=5000)
    max_scan_duration_seconds: int = Field(default=600, ge=60, le=86400)
    aggressive_max_discovered_assets: int = Field(default=500, ge=1, le=10000)
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
        81,
        110,
        111,
        135,
        139,
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
        1883,
        2049,
        2181,
        2375,
        2376,
        2379,
        2380,
        3000,
        3128,
        3306,
        3389,
        4443,
        5000,
        5432,
        5601,
        5672,
        5900,
        5984,
        6379,
        6443,
        7001,
        7002,
        8000,
        8080,
        8081,
        8443,
        8500,
        8888,
        9000,
        9090,
        9200,
        9300,
        9418,
        9443,
        10000,
        10250,
        10255,
        11211,
        15672,
        27017,
        27018,
    ]


def _validate_settings(settings: Settings) -> None:
    if settings.environment != "production":
        return

    errors: list[str] = []
    if settings.debug:
        errors.append("DEBUG must be false")
    if settings.secret_key in {
        "change-me-in-production",
        "change-this-to-a-long-random-secret",
        "development-only-change-me-32-bytes",
    } or len(settings.secret_key) < 32:
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
        secret_key=os.getenv("SECRET_KEY", "development-only-change-me-32-bytes"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", str(60 * 8))),
        algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        cors_origins=cors_origins,
        allow_internal_targets=os.getenv("ALLOW_INTERNAL_TARGETS", "false").lower() == "true",
        scan_timeout_seconds=float(os.getenv("SCAN_TIMEOUT_SECONDS", "3.0")),
        discovery_timeout_seconds=float(os.getenv("DISCOVERY_TIMEOUT_SECONDS", "10.0")),
        scan_concurrency=int(os.getenv("SCAN_CONCURRENCY", "5")),
        port_scan_concurrency=int(os.getenv("PORT_SCAN_CONCURRENCY", "20")),
        asset_timeout_seconds=int(os.getenv("ASSET_TIMEOUT_SECONDS", "45")),
        aggressive_asset_timeout_seconds=int(os.getenv("AGGRESSIVE_ASSET_TIMEOUT_SECONDS", "120")),
        max_http_body_bytes=int(os.getenv("MAX_HTTP_BODY_BYTES", "65536")),
        max_exposure_endpoints=int(os.getenv("MAX_EXPOSURE_ENDPOINTS", "12")),
        inline_scan_runner=os.getenv("INLINE_SCAN_RUNNER", "true").lower() == "true",
        max_discovered_assets=int(os.getenv("MAX_DISCOVERED_ASSETS", "250")),
        max_scan_duration_seconds=int(os.getenv("MAX_SCAN_DURATION_SECONDS", "600")),
        aggressive_max_discovered_assets=int(os.getenv("AGGRESSIVE_MAX_DISCOVERED_ASSETS", "500")),
        default_ports=default_ports,
        aggressive_ports=aggressive_ports,
    )
    _validate_settings(settings)
    return settings
