from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from sqlalchemy import select

from app.database import SessionLocal
from app.models import Scan, ScanLog
from app.models.mixins import utc_now
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.scanner.orchestrator import run_project_scan
from app.schemas.scan import ScanLogRead, ScanRead
from app.services.audit import record_audit

router = APIRouter(tags=["scans"])


def _run_scan_task(scan_id: str) -> None:
    db = SessionLocal()
    try:
        run_project_scan(scan_id, db)
    finally:
        db.close()


@router.post("/projects/{project_id}/scans", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def start_scan(project_id: str, background_tasks: BackgroundTasks, db: DbSession, current_user: CurrentUser) -> Scan:
    project = get_owned_project(project_id, db, current_user)
    if not project.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    scan = Scan(project_id=project.id, status="pending", trigger="manual", started_at=None)
    db.add(scan)
    record_audit(db, "scan.started", current_user.id, "project", project.id)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_run_scan_task, scan.id)
    return scan


@router.get("/projects/{project_id}/scans", response_model=list[ScanRead])
def list_project_scans(project_id: str, db: DbSession, current_user: CurrentUser) -> list[Scan]:
    project = get_owned_project(project_id, db, current_user)
    return list(db.scalars(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc())))


@router.get("/scans/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: str, db: DbSession, current_user: CurrentUser) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    get_owned_project(scan.project_id, db, current_user)
    return scan


@router.get("/scans/{scan_id}/logs", response_model=list[ScanLogRead])
def get_scan_logs(scan_id: str, db: DbSession, current_user: CurrentUser) -> list[ScanLog]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    get_owned_project(scan.project_id, db, current_user)
    return list(db.scalars(select(ScanLog).where(ScanLog.scan_id == scan.id).order_by(ScanLog.created_at.asc())))


@router.post("/scans/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: str, db: DbSession, current_user: CurrentUser) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    get_owned_project(scan.project_id, db, current_user)
    if scan.status not in {"pending", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending or running scans can be cancelled.")
    scan.status = "cancelled"
    scan.finished_at = utc_now()
    record_audit(db, "scan.cancelled", current_user.id, "scan", scan.id)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/scans/{scan_id}/retry", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def retry_scan(scan_id: str, background_tasks: BackgroundTasks, db: DbSession, current_user: CurrentUser) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    project = get_owned_project(scan.project_id, db, current_user)
    retry = Scan(project_id=project.id, status="pending", trigger="retry")
    db.add(retry)
    record_audit(db, "scan.retried", current_user.id, "scan", scan.id)
    db.commit()
    db.refresh(retry)
    background_tasks.add_task(_run_scan_task, retry.id)
    return retry
