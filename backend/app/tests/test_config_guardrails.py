import pytest

from app.config import get_settings


def test_production_settings_reject_placeholder_secrets(monkeypatch) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://surfacewatch:pw@db:5432/surfacewatch")
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production")
    monkeypatch.setenv("CORS_ORIGINS", '["https://surfacewatch.example"]')
    try:
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            get_settings()
    finally:
        get_settings.cache_clear()
