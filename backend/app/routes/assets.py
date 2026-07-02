from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models import Asset
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.asset import AssetRead

router = APIRouter(tags=["assets"])


@router.get("/projects/{project_id}/assets", response_model=list[AssetRead])
def list_project_assets(project_id: str, db: DbSession, current_user: CurrentUser) -> list[Asset]:
    project = get_owned_project(project_id, db, current_user)
    return list(
        db.scalars(
            select(Asset)
            .where(Asset.project_id == project.id)
            .options(selectinload(Asset.ports), selectinload(Asset.technologies))
            .order_by(Asset.hostname.asc())
        )
    )


@router.get("/assets/{asset_id}", response_model=AssetRead)
def get_asset(asset_id: str, db: DbSession, current_user: CurrentUser) -> Asset:
    asset = db.scalar(
        select(Asset)
        .where(Asset.id == asset_id)
        .options(selectinload(Asset.ports), selectinload(Asset.technologies))
    )
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    get_owned_project(asset.project_id, db, current_user)
    return asset
