from datetime import timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base
from app.models import Asset, Finding, Project, Scan, User
from app.models.mixins import utc_now
from app.scanner.orchestrator import _create_finding


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return TestingSessionLocal()


def test_scanner_reopens_fixed_finding_when_same_fingerprint_is_seen_again() -> None:
    db = _session()
    try:
        now = utc_now()
        user = User(email="finding@example.org", full_name="Finding Tester", hashed_password="hash")
        project = Project(
            owner=user,
            company_name="Finding Org",
            main_domain="example.org",
            authorization_confirmed=True,
            authorization_contact="owner@example.org",
            authorization_expires_at=now + timedelta(days=30),
        )
        scan = Scan(project=project, status="running")
        asset = Asset(project=project, scan=scan, hostname="example.org", first_seen_at=now, last_seen_at=now)
        db.add_all([user, project, scan, asset])
        db.flush()

        _create_finding(
            db,
            project,
            scan,
            asset,
            "Development port exposed",
            "A development service is reachable.",
            "high",
            "Exposed Services",
            {"port": 3000},
            "Development services may expose sensitive data.",
            "Restrict access to trusted networks.",
        )
        db.flush()

        finding = db.scalar(select(Finding).where(Finding.project_id == project.id))
        assert finding is not None
        first_id = finding.id
        assert finding.fingerprint
        assert finding.evidence_hash
        assert finding.confidence == "high"
        assert finding.cvss_score == 8.0
        assert finding.sla_due_at is not None

        finding.status = "fixed"
        db.flush()

        _create_finding(
            db,
            project,
            scan,
            asset,
            "Development port exposed",
            "A development service is reachable.",
            "high",
            "Exposed Services",
            {"port": 3000},
            "Development services may expose sensitive data.",
            "Restrict access to trusted networks.",
        )
        db.flush()

        findings = list(db.scalars(select(Finding).where(Finding.project_id == project.id)))
        assert len(findings) == 1
        assert findings[0].id == first_id
        assert findings[0].status == "open"
    finally:
        db.close()
