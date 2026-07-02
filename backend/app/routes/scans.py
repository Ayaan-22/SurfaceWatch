from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from sqlalchemy import func, select

from app.database import SessionLocal
from app.models import Asset, Finding, Notification, Project, Scan, ScanLog
from app.models.mixins import utc_now
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.scanner.orchestrator import run_project_scan
from app.scanner.risk_engine import calculate_risk_score
from app.schemas.scan import ScanLogRead, ScanRead
from app.services.audit import record_audit

router = APIRouter(tags=["scans"])


def _run_scan_task(scan_id: str) -> None:
    db = SessionLocal()
    try:
        run_project_scan(scan_id, db)
    finally:
        db.close()


def _sync_scan_summary(db: DbSession, scan: Scan) -> None:
    assets_scanned = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id)) or 0
    severities = list(db.scalars(select(Finding.severity).where(Finding.scan_id == scan.id)))
    risk_score, risk_level, _ = calculate_risk_score(severities)

    scan.assets_scanned = assets_scanned
    scan.findings_created = len(severities)
    scan.risk_score = risk_score

    project = db.get(Project, scan.project_id)
    if project is not None and scan.status in {"completed", "cancelled"}:
        project.risk_score = risk_score
        project.risk_level = risk_level
        project.risk_status = "attention_required" if risk_score > 50 else "monitored"
        project.last_scan_at = scan.finished_at or project.last_scan_at


def _repair_stale_scan_summary(db: DbSession, scan: Scan) -> bool:
    if scan.status not in {"completed", "cancelled", "failed"}:
        return False
    related_assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id)) or 0
    related_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0
    if scan.assets_scanned == related_assets and scan.findings_created == related_findings:
        return False
    _sync_scan_summary(db, scan)
    return True


def _scan_notification(db: DbSession, user_id: str, scan: Scan) -> Notification | None:
    notifications = db.scalars(
        select(Notification).where(
            Notification.user_id == user_id,
            Notification.project_id == scan.project_id,
            Notification.notification_type.in_(["scan_completed", "scan_cancelled"]),
        )
    )
    for notification in notifications:
        metadata = notification.metadata_json or {}
        if isinstance(metadata, dict) and metadata.get("scan_id") == scan.id:
            return notification
    return None


def _upsert_cancelled_scan_notification(db: DbSession, project: Project, scan: Scan, user_id: str) -> None:
    notification = _scan_notification(db, user_id, scan)
    if notification is None:
        notification = Notification(
            user_id=user_id,
            project_id=project.id,
            title="Scan cancelled",
            message=f"{project.company_name} scan was cancelled after {scan.assets_scanned} assets. Risk score: {scan.risk_score}.",
            notification_type="scan_cancelled",
            metadata_json={"scan_id": scan.id, "risk_score": scan.risk_score},
        )
        db.add(notification)
        return

    notification.title = "Scan cancelled"
    notification.message = f"{project.company_name} scan was cancelled after {scan.assets_scanned} assets. Risk score: {scan.risk_score}."
    notification.notification_type = "scan_cancelled"
    notification.metadata_json = {"scan_id": scan.id, "risk_score": scan.risk_score}
    notification.is_read = False


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
    if _repair_stale_scan_summary(db, scan):
        db.commit()
        db.refresh(scan)
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
    project = get_owned_project(scan.project_id, db, current_user)
    if scan.status not in {"pending", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only pending or running scans can be cancelled.")
    scan.status = "cancelled"
    scan.finished_at = utc_now()
    _sync_scan_summary(db, scan)
    _upsert_cancelled_scan_notification(db, project, scan, current_user.id)
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
