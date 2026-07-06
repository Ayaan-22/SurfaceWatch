from collections.abc import Generator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app import models  # noqa: F401


FUTURE_AUTH_EXPIRY = "2027-07-03T23:59:59Z"


@contextmanager
def _client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    Base.metadata.create_all(bind=engine)

    def override_db() -> Generator[Session, None, None]:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def test_protected_projects_requires_authentication() -> None:
    with _client() as client:
        response = client.get("/api/v1/projects")
        assert response.status_code == 401


def test_register_login_and_project_crud() -> None:
    with _client() as client:
        register_response = client.post(
            "/api/v1/auth/register",
            json={"email": "analyst@example.org", "full_name": "Security Analyst", "password": "StrongPass123!"},
        )
        assert register_response.status_code == 201

        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@example.org", "password": "StrongPass123!"},
        )
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        unauthorized_scope = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "company_name": "Example Org",
                "main_domain": "example.org",
                "description": "Missing authorization checkbox",
                "scan_frequency": "manual",
                "authorization_confirmed": False,
                "authorization_contact": "owner@example.org",
                "authorization_expires_at": FUTURE_AUTH_EXPIRY,
            },
        )
        assert unauthorized_scope.status_code == 400

        missing_evidence = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "company_name": "Example Org",
                "main_domain": "example.org",
                "description": "Missing authorization evidence",
                "scan_frequency": "manual",
                "authorization_confirmed": True,
            },
        )
        assert missing_evidence.status_code == 400

        create_response = client.post(
            "/api/v1/projects",
            headers=headers,
            json={
                "company_name": "Example Org",
                "main_domain": "https://example.org/app",
                "description": "Authorized public scope",
                "scan_frequency": "weekly",
                "authorization_confirmed": True,
                "authorization_contact": "owner@example.org",
                "authorization_expires_at": FUTURE_AUTH_EXPIRY,
                "max_scan_profile": "aggressive",
            },
        )
        assert create_response.status_code == 201
        project = create_response.json()
        assert project["main_domain"] == "example.org"
        assert project["authorization_contact"] == "owner@example.org"
        assert project["max_scan_profile"] == "aggressive"

        list_response = client.get("/api/v1/projects", headers=headers)
        assert list_response.status_code == 200
        assert len(list_response.json()) == 1
