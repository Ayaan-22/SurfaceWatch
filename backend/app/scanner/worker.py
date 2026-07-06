import logging
import time

from sqlalchemy import select

from app.database import SessionLocal
from app.models import Scan
from app.scanner.orchestrator import run_project_scan

logger = logging.getLogger(__name__)


def claim_next_scan() -> str | None:
    db = SessionLocal()
    try:
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
        scan.status = "running"
        db.commit()
        return scan.id
    finally:
        db.close()


def run_scan_worker(poll_interval_seconds: float = 2.0, once: bool = False) -> None:
    logger.info("SurfaceWatch scan worker started.")
    while True:
        scan_id = claim_next_scan()
        if scan_id is None:
            if once:
                return
            time.sleep(poll_interval_seconds)
            continue

        db = SessionLocal()
        try:
            run_project_scan(scan_id, db)
        finally:
            db.close()

        if once:
            return
