from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Scan, ScheduledJob
from app.models.mixins import utc_now
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.routes.scans import _run_scan_task
from app.scanner.scheduler import next_run
from app.schemas.scheduled_job import ScheduledJobRead, ScheduledJobUpdate
from app.services.audit import record_audit

router = APIRouter(tags=["scheduled jobs"])


@router.get("/projects/{project_id}/schedule", response_model=ScheduledJobRead)
def get_project_schedule(project_id: str, db: DbSession, current_user: CurrentUser) -> ScheduledJob:
    project = get_owned_project(project_id, db, current_user)
    job = db.scalar(select(ScheduledJob).where(ScheduledJob.project_id == project.id, ScheduledJob.job_type == "scan"))
    if job is None:
        job = ScheduledJob(
            project_id=project.id,
            frequency=project.scan_frequency,
            status="active" if project.scan_frequency != "manual" else "paused",
            next_run_at=next_run(project.scan_frequency),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
    return job


@router.patch("/projects/{project_id}/schedule", response_model=ScheduledJobRead)
def update_project_schedule(
    project_id: str,
    payload: ScheduledJobUpdate,
    db: DbSession,
    current_user: CurrentUser,
) -> ScheduledJob:
    project = get_owned_project(project_id, db, current_user)
    job = db.scalar(select(ScheduledJob).where(ScheduledJob.project_id == project.id, ScheduledJob.job_type == "scan"))
    if job is None:
        job = ScheduledJob(project_id=project.id, job_type="scan")
        db.add(job)
    job.frequency = payload.frequency
    job.status = payload.status if payload.frequency != "manual" else "paused"
    job.next_run_at = next_run(payload.frequency) if job.status == "active" else None
    project.scan_frequency = payload.frequency
    project.next_scan_at = job.next_run_at
    record_audit(db, "schedule.updated", current_user.id, "project", project.id, metadata={"frequency": payload.frequency, "status": job.status})
    db.commit()
    db.refresh(job)
    return job


@router.post("/scheduled-jobs/run-due", response_model=list[ScheduledJobRead])
def run_due_jobs(background_tasks: BackgroundTasks, db: DbSession, current_user: CurrentUser) -> list[ScheduledJob]:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
    now = utc_now()
    jobs = list(
        db.scalars(
            select(ScheduledJob).where(
                ScheduledJob.status == "active",
                ScheduledJob.next_run_at.is_not(None),
                ScheduledJob.next_run_at <= now,
            )
        )
    )
    for job in jobs:
        scan = Scan(project_id=job.project_id, status="pending", trigger="scheduled")
        db.add(scan)
        db.flush()
        job.last_run_at = now
        job.next_run_at = next_run(job.frequency, now)
        background_tasks.add_task(_run_scan_task, scan.id)
    record_audit(db, "scheduled_jobs.run_due", current_user.id, metadata={"count": len(jobs)})
    db.commit()
    return jobs
