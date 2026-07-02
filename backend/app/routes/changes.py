from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.models import Change, Scan
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.change import ChangeRead

router = APIRouter(tags=["changes"])


@router.get("/projects/{project_id}/changes", response_model=list[ChangeRead])
def list_project_changes(project_id: str, db: DbSession, current_user: CurrentUser) -> list[Change]:
    project = get_owned_project(project_id, db, current_user)
    return list(db.scalars(select(Change).where(Change.project_id == project.id).order_by(Change.detected_at.desc()).limit(100)))


@router.get("/scans/{scan_id}/changes", response_model=list[ChangeRead])
def list_scan_changes(scan_id: str, db: DbSession, current_user: CurrentUser) -> list[Change]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    get_owned_project(scan.project_id, db, current_user)
    return list(db.scalars(select(Change).where(Change.scan_id == scan.id).order_by(Change.detected_at.desc())))
