from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base
from app.models import Finding, Project, Scan, User
from app.models.mixins import utc_now
from app.routes.projects import get_project
from app.routes.scans import _sync_scan_summary
from app.services.risk import sync_project_risk


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return TestingSessionLocal()


def test_scan_summary_does_not_zero_project_risk_when_open_findings_remain() -> None:
    db = _session()
    try:
        user = User(email="risk@example.org", full_name="Risk Tester", hashed_password="hash")
        project = Project(
            owner=user,
            company_name="Risk Org",
            main_domain="example.org",
            authorization_confirmed=True,
            authorization_contact="owner@example.org",
            authorization_expires_at=utc_now(),
            risk_score=100,
            risk_level="critical",
            risk_status="attention_required",
        )
        old_scan = Scan(project=project, status="completed", finished_at=utc_now(), risk_score=100)
        db.add_all([user, project, old_scan])
        db.flush()

        now = utc_now()
        for index in range(4):
            db.add(
                Finding(
                    project_id=project.id,
                    scan_id=old_scan.id,
                    title=f"Critical finding {index}",
                    description="An unresolved critical issue.",
                    severity="critical",
                    category="Exposure",
                    first_seen_at=now,
                    last_seen_at=now,
                    status="open",
                )
            )
        sync_project_risk(db, project)
        assert project.risk_score == 100

        latest_scan = Scan(project=project, status="completed", finished_at=utc_now(), risk_score=0)
        db.add(latest_scan)
        db.flush()

        _sync_scan_summary(db, latest_scan)

        assert latest_scan.risk_score == 0
        assert latest_scan.findings_created == 0
        assert project.risk_score == 100
        assert project.risk_level == "critical"
        assert project.risk_status == "attention_required"
    finally:
        db.close()


def test_project_read_repairs_stale_project_risk() -> None:
    db = _session()
    try:
        user = User(email="stale-risk@example.org", full_name="Risk Tester", hashed_password="hash")
        project = Project(
            owner=user,
            company_name="Risk Org",
            main_domain="example.org",
            authorization_confirmed=True,
            authorization_contact="owner@example.org",
            authorization_expires_at=utc_now(),
            risk_score=0,
            risk_level="low",
            risk_status="monitored",
        )
        scan = Scan(project=project, status="completed", finished_at=utc_now(), risk_score=100)
        db.add_all([user, project, scan])
        db.flush()

        now = utc_now()
        for index in range(4):
            db.add(
                Finding(
                    project_id=project.id,
                    scan_id=scan.id,
                    title=f"Critical finding {index}",
                    description="An unresolved critical issue.",
                    severity="critical",
                    category="Exposure",
                    first_seen_at=now,
                    last_seen_at=now,
                    status="open",
                )
            )

        repaired = get_project(project.id, db, user)

        assert repaired.risk_score == 100
        assert repaired.risk_level == "critical"
        assert repaired.risk_status == "attention_required"
    finally:
        db.close()
