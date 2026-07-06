from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.models import Finding, FindingNote
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.finding import FindingNoteCreate, FindingNoteRead, FindingRead, FindingStatusUpdate
from app.services.audit import record_audit
from app.services.risk import sync_project_risk

router = APIRouter(tags=["findings"])


@router.get("/projects/{project_id}/findings", response_model=list[FindingRead])
def list_project_findings(project_id: str, db: DbSession, current_user: CurrentUser) -> list[Finding]:
    project = get_owned_project(project_id, db, current_user)
    return list(db.scalars(select(Finding).where(Finding.project_id == project.id).order_by(Finding.last_seen_at.desc())))


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: str, db: DbSession, current_user: CurrentUser) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    get_owned_project(finding.project_id, db, current_user)
    return finding


@router.patch("/findings/{finding_id}/status", response_model=FindingRead)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: DbSession,
    current_user: CurrentUser,
) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    project = get_owned_project(finding.project_id, db, current_user)
    finding.status = payload.status
    if payload.notes is not None:
        finding.notes = payload.notes
        db.add(FindingNote(finding_id=finding.id, user_id=current_user.id, note=payload.notes))
    sync_project_risk(db, project)
    record_audit(db, "finding.status_updated", current_user.id, "finding", finding.id, metadata={"status": payload.status})
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}/notes", response_model=list[FindingNoteRead])
def list_finding_notes(finding_id: str, db: DbSession, current_user: CurrentUser) -> list[FindingNote]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    get_owned_project(finding.project_id, db, current_user)
    return list(db.scalars(select(FindingNote).where(FindingNote.finding_id == finding.id).order_by(FindingNote.created_at.desc())))


@router.post("/findings/{finding_id}/notes", response_model=FindingNoteRead, status_code=status.HTTP_201_CREATED)
def create_finding_note(
    finding_id: str,
    payload: FindingNoteCreate,
    db: DbSession,
    current_user: CurrentUser,
) -> FindingNote:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    get_owned_project(finding.project_id, db, current_user)
    note = FindingNote(finding_id=finding.id, user_id=current_user.id, note=payload.note)
    finding.notes = payload.note
    db.add(note)
    record_audit(db, "finding.note_created", current_user.id, "finding", finding.id)
    db.commit()
    db.refresh(note)
    return note
