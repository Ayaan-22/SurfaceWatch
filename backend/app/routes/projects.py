from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.config import get_settings
from app.models import Project
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate
from app.utils.domain_validation import validate_public_domain

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectRead])
def list_projects(db: DbSession, current_user: CurrentUser) -> list[Project]:
    return list(
        db.scalars(select(Project).where(Project.owner_id == current_user.id).order_by(Project.created_at.desc()))
    )


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, db: DbSession, current_user: CurrentUser) -> Project:
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authorization confirmation is required before adding a domain.",
        )

    validation = validate_public_domain(payload.main_domain, get_settings().allow_internal_targets)
    if not validation.is_valid:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=validation.reason)

    project = Project(
        owner_id=current_user.id,
        company_name=payload.company_name.strip(),
        main_domain=validation.normalized,
        description=payload.description,
        authorization_confirmed=True,
        scan_frequency=payload.scan_frequency,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: str, db: DbSession, current_user: CurrentUser) -> Project:
    return get_owned_project(project_id, db, current_user)


@router.patch("/{project_id}", response_model=ProjectRead)
def update_project(
    project_id: str,
    payload: ProjectUpdate,
    db: DbSession,
    current_user: CurrentUser,
) -> Project:
    project = get_owned_project(project_id, db, current_user)
    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if value is not None:
            setattr(project, field, value.strip() if isinstance(value, str) else value)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: str, db: DbSession, current_user: CurrentUser) -> None:
    project = get_owned_project(project_id, db, current_user)
    db.delete(project)
    db.commit()
