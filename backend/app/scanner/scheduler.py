from datetime import datetime, timedelta, timezone
import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Project, Scan, ScheduledJob
from app.models.mixins import utc_now


logger = logging.getLogger(__name__)


def next_run(scan_frequency: str, from_time: datetime | None = None) -> datetime | None:
    base = from_time or datetime.now(timezone.utc)
    if scan_frequency == "daily":
        return base + timedelta(days=1)
    if scan_frequency == "weekly":
        return base + timedelta(weeks=1)
    if scan_frequency == "monthly":
        return base + timedelta(days=30)
    return None


def _authorization_is_current(project: Project, now: datetime) -> bool:
    expires_at = project.authorization_expires_at
    if not project.authorization_confirmed or expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at.astimezone(timezone.utc) > now


def enqueue_due_scans(db: Session, now: datetime | None = None) -> list[ScheduledJob]:
    """Atomically enqueue due jobs; workers remain the sole production runners."""
    current = now or utc_now()
    jobs = list(
        db.scalars(
            select(ScheduledJob)
            .where(
                ScheduledJob.status == "active",
                ScheduledJob.next_run_at.is_not(None),
                ScheduledJob.next_run_at <= current,
            )
            .order_by(ScheduledJob.next_run_at.asc())
            .with_for_update(skip_locked=True)
        )
    )
    enqueued: list[ScheduledJob] = []
    for job in jobs:
        project = db.get(Project, job.project_id)
        if project is None or not _authorization_is_current(project, current):
            job.status = "paused"
            job.next_run_at = None
            continue
        active_scan = db.scalar(
            select(Scan).where(
                Scan.project_id == job.project_id,
                Scan.status.in_(["queued", "pending", "claimed", "running"]),
            )
        )
        if active_scan is None:
            db.add(Scan(project_id=job.project_id, status="queued", trigger="scheduled", scan_profile="safe"))
            db.flush()
            job.last_run_at = current
            enqueued.append(job)
        job.next_run_at = next_run(job.frequency, current)
    db.commit()
    return enqueued


def run_scan_scheduler(poll_interval_seconds: float = 30.0, once: bool = False) -> None:
    logger.info("SurfaceWatch scheduler started.")
    while True:
        db = SessionLocal()
        try:
            enqueued = enqueue_due_scans(db)
            if enqueued:
                logger.info("Enqueued %d due scan(s).", len(enqueued))
        except Exception:
            db.rollback()
            logger.exception("Scheduled scan dispatch failed; scheduler will continue.")
        finally:
            db.close()
        if once:
            return
        time.sleep(max(1.0, poll_interval_seconds))
