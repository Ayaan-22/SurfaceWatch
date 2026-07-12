from datetime import timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base
from app.models import Project, Scan, ScheduledJob, User
from app.models.mixins import utc_now
from app.scanner.scheduler import enqueue_due_scans


def _session() -> Session:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def _scheduled_project(db: Session, *, expired: bool = False) -> tuple[Project, ScheduledJob]:
    now = utc_now()
    user = User(email=f"scheduler-{expired}@example.org", full_name="Scheduler", hashed_password="hash")
    project = Project(
        owner=user,
        company_name="Scheduled Org",
        main_domain=f"scheduled-{expired}.example.org",
        authorization_confirmed=True,
        authorization_contact="owner@example.org",
        authorization_expires_at=now - timedelta(seconds=1) if expired else now + timedelta(days=30),
        scan_frequency="daily",
    )
    job = ScheduledJob(
        project=project,
        frequency="daily",
        status="active",
        next_run_at=now - timedelta(minutes=1),
    )
    db.add_all([user, project, job])
    db.commit()
    return project, job


def test_scheduler_enqueues_once_and_does_not_overlap_active_scan() -> None:
    db = _session()
    try:
        project, job = _scheduled_project(db)
        now = utc_now()

        assert enqueue_due_scans(db, now) == [job]
        assert db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project.id)) == 1

        job.next_run_at = now - timedelta(seconds=1)
        db.commit()
        assert enqueue_due_scans(db, now) == []
        assert db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project.id)) == 1
    finally:
        db.close()


def test_scheduler_pauses_jobs_when_authorization_has_expired() -> None:
    db = _session()
    try:
        project, job = _scheduled_project(db, expired=True)

        assert enqueue_due_scans(db) == []
        db.refresh(job)
        assert job.status == "paused"
        assert job.next_run_at is None
        assert db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project.id)) == 0
    finally:
        db.close()
