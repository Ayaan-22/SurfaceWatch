import logging
import time
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import SessionLocal
from app.models import Scan, ScanAssetResult, ScanLog
from app.models.mixins import utc_now
from app.scanner.orchestrator import run_project_scan

logger = logging.getLogger(__name__)


def _recover_stale_scans(db: Session) -> None:
    """Release abandoned claims and terminate workers that exceeded the global lease."""
    now = utc_now()
    settings = get_settings()
    claim_cutoff = now - timedelta(minutes=2)
    running_cutoff = now - timedelta(seconds=settings.max_scan_duration_seconds + 120)
    for scan in db.scalars(select(Scan).where(Scan.status == "claimed", Scan.updated_at < claim_cutoff)):
        scan.status = "queued"
        scan.worker_token = None
        scan.error_message = "Recovered an abandoned worker claim."
        db.add(ScanLog(scan_id=scan.id, level="warning", message=scan.error_message))
    for scan in db.scalars(select(Scan).where(Scan.status == "running", Scan.updated_at < running_cutoff)):
        failure_message = "Scan worker heartbeat expired before completion. Partial manifests were preserved."
        unfinished = list(
            db.scalars(
                select(ScanAssetResult).where(
                    ScanAssetResult.scan_id == scan.id,
                    ScanAssetResult.scan_status.in_(["pending", "running"]),
                )
            )
        )
        expected_checks = 5 if scan.scan_profile == "aggressive" else 4
        for manifest in unfinished:
            manifest.scan_status = "not_scanned"
            manifest.finished_at = now
            manifest.checks = {
                "scan": {
                    "status": "failed",
                    "planned": expected_checks,
                    "completed": 0,
                    "error": failure_message,
                }
            }
            manifest.errors = [*(manifest.errors or []), {"stage": "worker", "error": failure_message}]
        scan.status = "failed"
        scan.finished_at = now
        scan.worker_token = None
        scan.heartbeat_at = now
        scan.assets_failed += len(unfinished)
        scan.checks_failed += len(unfinished) * expected_checks
        planned_checks = scan.assets_discovered * expected_checks
        scan.coverage_percent = min(100, round((scan.checks_completed / planned_checks) * 100)) if planned_checks else 0
        scan.partial_reason = failure_message
        scan.error_message = failure_message
        db.add(ScanLog(scan_id=scan.id, level="error", message=scan.error_message))
    db.commit()


def claim_next_scan() -> tuple[str, str] | None:
    db = SessionLocal()
    try:
        _recover_stale_scans(db)
        statement = (
            select(Scan)
            .where(Scan.status.in_(["queued", "pending"]))
            .order_by(Scan.created_at.asc())
            .with_for_update(skip_locked=True)
        )
        scan = db.scalar(statement)
        if scan is None:
            db.commit()
            return None
        # The random lease token prevents an expired worker from stealing a
        # replacement worker's claim after status recovery.
        worker_token = uuid.uuid4().hex
        scan.status = "claimed"
        scan.worker_token = worker_token
        scan.heartbeat_at = utc_now()
        scan.attempt_count += 1
        db.commit()
        return scan.id, worker_token
    finally:
        db.close()


def run_scan_worker(poll_interval_seconds: float = 2.0, once: bool = False) -> None:
    logger.info("SurfaceWatch scan worker started.")
    while True:
        claim = claim_next_scan()
        if claim is None:
            if once:
                return
            time.sleep(poll_interval_seconds)
            continue

        scan_id, worker_token = claim

        db = SessionLocal()
        try:
            run_project_scan(scan_id, db, claimed=True, worker_token=worker_token)
        except Exception:
            logger.exception("Unhandled worker error while executing scan %s; worker will continue.", scan_id)
        finally:
            db.close()

        if once:
            return
