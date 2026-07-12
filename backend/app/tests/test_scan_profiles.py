from collections.abc import Generator
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base, get_db
from app.main import app


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


def _auth_headers(client: TestClient) -> dict[str, str]:
    register_response = client.post(
        "/api/v1/auth/register",
        json={"email": "profile@example.org", "full_name": "Profile Tester", "password": "StrongPass123!"},
    )
    assert register_response.status_code == 201
    login_response = client.post("/api/v1/auth/login", json={"email": "profile@example.org", "password": "StrongPass123!"})
    assert login_response.status_code == 200
    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


def _project_id(client: TestClient, headers: dict[str, str], max_scan_profile: str = "safe") -> str:
    response = client.post(
        "/api/v1/projects",
        headers=headers,
        json={
            "company_name": "Example Org",
            "main_domain": "example.org",
            "description": "Authorized public scope",
            "scan_frequency": "manual",
            "authorization_confirmed": True,
            "authorization_contact": "owner@example.org",
            "authorization_expires_at": FUTURE_AUTH_EXPIRY,
            "max_scan_profile": max_scan_profile,
        },
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def test_start_scan_accepts_explicit_aggressive_profile(monkeypatch) -> None:
    monkeypatch.setattr("app.routes.scans._run_scan_task", lambda scan_id: None)
    with _client() as client:
        headers = _auth_headers(client)
        project_id = _project_id(client, headers, max_scan_profile="aggressive")

        response = client.post(
            f"/api/v1/projects/{project_id}/scans",
            headers=headers,
            json={"scan_profile": "aggressive"},
        )

        assert response.status_code == 202
        body = response.json()
        assert body["scan_profile"] == "aggressive"
        assert body["trigger"] == "manual"


def test_start_scan_rejects_aggressive_profile_outside_authorized_scope(monkeypatch) -> None:
    monkeypatch.setattr("app.routes.scans._run_scan_task", lambda scan_id: None)
    with _client() as client:
        headers = _auth_headers(client)
        project_id = _project_id(client, headers)

        response = client.post(
            f"/api/v1/projects/{project_id}/scans",
            headers=headers,
            json={"scan_profile": "aggressive"},
        )

        assert response.status_code == 403


def test_start_scan_defaults_to_safe_profile(monkeypatch) -> None:
    monkeypatch.setattr("app.routes.scans._run_scan_task", lambda scan_id: None)
    with _client() as client:
        headers = _auth_headers(client)
        project_id = _project_id(client, headers)

        response = client.post(f"/api/v1/projects/{project_id}/scans", headers=headers)

        assert response.status_code == 202
        assert response.json()["scan_profile"] == "safe"


def test_queued_manual_scan_can_be_cancelled_before_worker_starts(monkeypatch) -> None:
    monkeypatch.setattr("app.routes.scans._run_scan_task", lambda scan_id: None)
    with _client() as client:
        headers = _auth_headers(client)
        project_id = _project_id(client, headers)

        start_response = client.post(f"/api/v1/projects/{project_id}/scans", headers=headers)
        assert start_response.status_code == 202
        queued_scan = start_response.json()
        assert queued_scan["status"] == "queued"
        assert queued_scan["started_at"] is None

        cancel_response = client.post(f"/api/v1/scans/{queued_scan['id']}/cancel", headers=headers)

        assert cancel_response.status_code == 200
        cancelled_scan = cancel_response.json()
        assert cancelled_scan["status"] == "cancelled"
        assert cancelled_scan["started_at"] is None
        assert cancelled_scan["finished_at"] is not None


def test_project_rejects_overlapping_active_scans(monkeypatch) -> None:
    monkeypatch.setattr("app.routes.scans._run_scan_task", lambda scan_id: None)
    with _client() as client:
        headers = _auth_headers(client)
        project_id = _project_id(client, headers)

        first = client.post(f"/api/v1/projects/{project_id}/scans", headers=headers)
        second = client.post(f"/api/v1/projects/{project_id}/scans", headers=headers)

        assert first.status_code == 202
        assert second.status_code == 409
        assert first.json()["id"] in second.json()["detail"]
