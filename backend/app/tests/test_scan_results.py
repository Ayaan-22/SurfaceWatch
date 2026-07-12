from collections.abc import Generator
from contextlib import contextmanager
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base, get_db
from app.main import app
from app.models import Project, Scan, ScanAssetResult, User
from app.models.mixins import utc_now


@contextmanager
def _client() -> Generator[tuple[TestClient, sessionmaker[Session]], None, None]:
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
        with TestClient(app) as client:
            yield client, TestingSessionLocal
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)


def _register_and_login(client: TestClient, email: str) -> dict[str, str]:
    register_response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "full_name": "Scan Result Tester", "password": "StrongPass123!"},
    )
    assert register_response.status_code == 201
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": "StrongPass123!"})
    assert login_response.status_code == 200
    return {"Authorization": f"Bearer {login_response.json()['access_token']}"}


def test_scan_results_are_complete_and_owner_checked() -> None:
    with _client() as (client, session_factory):
        owner_headers = _register_and_login(client, "results-owner@example.org")
        outsider_headers = _register_and_login(client, "results-outsider@example.org")

        with session_factory() as db:
            owner = db.scalar(select(User).where(User.email == "results-owner@example.org"))
            assert owner is not None
            project = Project(
                owner_id=owner.id,
                company_name="Result Coverage Org",
                main_domain="example.org",
                authorization_confirmed=True,
                authorization_contact="owner@example.org",
                authorization_expires_at=utc_now() + timedelta(days=30),
            )
            scan = Scan(
                project=project,
                status="completed",
                assets_discovered=1,
                checks_completed=3,
                coverage_percent=75,
                discovery_metadata={"sources": {"certificate_transparency": "completed"}},
            )
            db.add_all([project, scan])
            db.flush()
            result = ScanAssetResult(
                project_id=project.id,
                scan=scan,
                hostname="api.example.org",
                ip_addresses=["93.184.216.34"],
                source="certificate_transparency",
                discovery_status="active",
                scan_status="completed",
                risk_level="medium",
                checks={"http": "completed", "tls": "completed", "ports": "completed"},
                http_observations=[{"url": "https://api.example.org", "status_code": 200}],
                tls_observations=[{"status": "healthy"}],
                port_observations=[{"port": 443, "status": "open"}],
                finding_observations=[{"title": "Missing CSP", "severity": "medium"}],
            )
            db.add(result)
            db.commit()
            scan_id = scan.id

        scan_response = client.get(f"/api/v1/scans/{scan_id}", headers=owner_headers)
        assert scan_response.status_code == 200
        scan_body = scan_response.json()
        assert scan_body["assets_discovered"] == 1
        assert scan_body["assets_failed"] == 0
        assert scan_body["checks_completed"] == 3
        assert scan_body["checks_failed"] == 0
        assert scan_body["coverage_percent"] == 75
        assert scan_body["partial_reason"] is None
        assert scan_body["discovery_metadata"]["sources"]["certificate_transparency"] == "completed"

        response = client.get(f"/api/v1/scans/{scan_id}/results", headers=owner_headers)
        assert response.status_code == 200
        assert response.json() == [
            {
                "id": response.json()[0]["id"],
                "project_id": response.json()[0]["project_id"],
                "scan_id": scan_id,
                "asset_id": None,
                "hostname": "api.example.org",
                "ip_addresses": ["93.184.216.34"],
                "source": "certificate_transparency",
                "discovery_status": "active",
                "scan_status": "completed",
                "risk_level": "medium",
                "checks": {"http": "completed", "tls": "completed", "ports": "completed"},
                "http_observations": [{"url": "https://api.example.org", "status_code": 200}],
                "tls_observations": [{"status": "healthy"}],
                "port_observations": [{"port": 443, "status": "open"}],
                "header_observations": [],
                "technology_observations": [],
                "exposure_observations": [],
                "finding_observations": [{"title": "Missing CSP", "severity": "medium"}],
                "errors": [],
                "started_at": None,
                "finished_at": None,
                "created_at": response.json()[0]["created_at"],
                "updated_at": response.json()[0]["updated_at"],
            }
        ]

        forbidden_response = client.get(f"/api/v1/scans/{scan_id}/results", headers=outsider_headers)
        assert forbidden_response.status_code == 404
