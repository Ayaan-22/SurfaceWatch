from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.models import Notification
from app.routes.deps import CurrentUser, DbSession
from app.schemas.notification import NotificationRead

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=list[NotificationRead])
def list_notifications(db: DbSession, current_user: CurrentUser) -> list[Notification]:
    return list(
        db.scalars(
            select(Notification)
            .where(Notification.user_id == current_user.id)
            .order_by(Notification.created_at.desc())
            .limit(50)
        )
    )


@router.patch("/{notification_id}/read", response_model=NotificationRead)
def mark_notification_read(notification_id: str, db: DbSession, current_user: CurrentUser) -> Notification:
    notification = db.get(Notification, notification_id)
    if notification is None or notification.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found.")
    notification.is_read = True
    db.commit()
    db.refresh(notification)
    return notification
