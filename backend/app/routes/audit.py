from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.models import AuditLog
from app.routes.deps import CurrentUser, DbSession
from app.schemas.audit import AuditLogRead

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(db: DbSession, current_user: CurrentUser) -> list[AuditLog]:
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required.")
    return list(db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(100)))
