from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Body, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.config import get_settings
from app.database import SessionLocal
from app.models import Asset, Finding, Notification, Project, Scan, ScanAssetResult, ScanLog
from app.models.mixins import utc_now
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.scanner.orchestrator import run_project_scan
from app.scanner.risk_engine import calculate_risk_score
from app.schemas.scan import ScanAssetResultRead, ScanLogRead, ScanRead, ScanStartRequest
from app.services.audit import record_audit
from app.services.risk import sync_project_risk

router = APIRouter(tags=["scans"])


def _to_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _run_scan_task(scan_id: str) -> None:
    db = SessionLocal()
    try:
        run_project_scan(scan_id, db)
    finally:
        db.close()


def _sync_scan_summary(db: DbSession, scan: Scan) -> None:
    result_rows = list(db.scalars(select(ScanAssetResult).where(ScanAssetResult.scan_id == scan.id)))
    if result_rows:
        processed_statuses = {"completed", "partial", "failed", "blocked", "unresolved", "timed_out"}
        failed_statuses = {"failed", "blocked", "timed_out"}
        severities: list[str] = []
        findings_count = 0
        checks_completed = 0
        checks_failed = 0
        for row in result_rows:
            for observation in row.finding_observations or []:
                if isinstance(observation, dict):
                    severity = observation.get("severity")
                    if isinstance(severity, str):
                        severities.append(severity)
                findings_count += 1
            for check in (row.checks or {}).values():
                if not isinstance(check, dict):
                    continue
                if check.get("status") in {"completed", "skipped"}:
                    checks_completed += 1
                elif check.get("status") in {"failed", "error"}:
                    checks_failed += 1
        risk_score, _, _ = calculate_risk_score(severities)
        scan.assets_discovered = len(result_rows)
        scan.assets_scanned = sum(row.scan_status in processed_statuses for row in result_rows)
        scan.assets_failed = sum(row.scan_status in failed_statuses for row in result_rows)
        scan.findings_created = findings_count
        scan.checks_completed = max(scan.checks_completed, checks_completed)
        scan.checks_failed = max(scan.checks_failed, checks_failed)
        scan.risk_score = risk_score
        return

    assets_scanned = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id)) or 0
    severities = list(db.scalars(select(Finding.severity).where(Finding.scan_id == scan.id)))
    risk_score, _, _ = calculate_risk_score(severities)

    scan.assets_scanned = assets_scanned
    scan.findings_created = len(severities)
    scan.risk_score = risk_score

    project = db.get(Project, scan.project_id)
    if project is not None and scan.status in {"completed", "partial", "cancelled"}:
        sync_project_risk(db, project)
        project.last_scan_at = scan.finished_at or project.last_scan_at


def _repair_stale_scan_summary(db: DbSession, scan: Scan) -> bool:
    if scan.status not in {"completed", "partial", "cancelled", "failed"}:
        return False
    snapshot_count = db.scalar(
        select(func.count()).select_from(ScanAssetResult).where(ScanAssetResult.scan_id == scan.id)
    ) or 0
    if snapshot_count:
        # Immutable manifests are authoritative; never compare historical scans
        # against mutable current-state Asset/Finding ownership.
        before = (scan.assets_discovered, scan.assets_scanned, scan.assets_failed, scan.findings_created, scan.risk_score)
        _sync_scan_summary(db, scan)
        after = (scan.assets_discovered, scan.assets_scanned, scan.assets_failed, scan.findings_created, scan.risk_score)
        return before != after
    related_assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.scan_id == scan.id)) or 0
    related_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan.id)) or 0
    if scan.assets_scanned == related_assets and scan.findings_created == related_findings:
        return False
    _sync_scan_summary(db, scan)
    return True


def _active_project_scan(db: DbSession, project_id: str) -> Scan | None:
    return db.scalar(
        select(Scan)
        .where(
            Scan.project_id == project_id,
            Scan.status.in_(["queued", "pending", "claimed", "running"]),
        )
        .order_by(Scan.created_at.asc())
    )


def _validate_scan_authorization(project: Project, scan_profile: str) -> None:
    if not project.authorization_confirmed:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization confirmation is required.")
    if project.authorization_expires_at is None or _to_aware_utc(project.authorization_expires_at) <= utc_now():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Authorization has expired or is missing an expiry.")
    if scan_profile == "aggressive" and project.max_scan_profile != "aggressive":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Aggressive scans require project authorization scope to allow aggressive scanning.",
        )


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
def start_scan(
    project_id: str,
    background_tasks: BackgroundTasks,
    db: DbSession,
    current_user: CurrentUser,
    payload: ScanStartRequest | None = Body(default=None),
) -> Scan:
    project = get_owned_project(project_id, db, current_user)
    scan_profile = payload.scan_profile if payload is not None else "safe"
    _validate_scan_authorization(project, scan_profile)
    active_scan = _active_project_scan(db, project.id)
    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {active_scan.id} is already {active_scan.status} for this project.",
        )
    settings = get_settings()
    scan = Scan(project_id=project.id, status="queued", trigger="manual", scan_profile=scan_profile, started_at=None)
    db.add(scan)
    record_audit(db, "scan.started", current_user.id, "project", project.id, metadata={"scan_profile": scan_profile})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Another active scan was created for this project.") from exc
    db.refresh(scan)
    if settings.inline_scan_runner:
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


@router.get("/scans/{scan_id}/results", response_model=list[ScanAssetResultRead])
def get_scan_results(scan_id: str, db: DbSession, current_user: CurrentUser) -> list[ScanAssetResult]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    get_owned_project(scan.project_id, db, current_user)
    return list(
        db.scalars(
            select(ScanAssetResult)
            .where(ScanAssetResult.scan_id == scan.id)
            .order_by(ScanAssetResult.hostname.asc())
        )
    )


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
    if scan.status not in {"queued", "pending", "claimed", "running"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only queued, claimed, or running scans can be cancelled.")
    scan.status = "cancelled"
    scan.finished_at = utc_now()
    scan.worker_token = None
    scan.heartbeat_at = scan.finished_at
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
    _validate_scan_authorization(project, scan.scan_profile)
    active_scan = _active_project_scan(db, project.id)
    if active_scan is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {active_scan.id} is already {active_scan.status} for this project.",
        )
    retry = Scan(project_id=project.id, status="queued", trigger="retry", scan_profile=scan.scan_profile)
    db.add(retry)
    record_audit(db, "scan.retried", current_user.id, "scan", scan.id)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Another active scan was created for this project.") from exc
    db.refresh(retry)
    if get_settings().inline_scan_runner:
        background_tasks.add_task(_run_scan_task, retry.id)
    return retry
