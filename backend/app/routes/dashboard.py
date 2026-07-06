from sqlalchemy import func, select

from fastapi import APIRouter

from app.models import Asset, Change, Finding, Port, Project, Scan, SecurityHeader, SslResult
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.project import DashboardSummary, ProjectRead
from app.services.risk import sync_project_risk

router = APIRouter(prefix="/projects", tags=["dashboard"])


@router.get("/{project_id}/dashboard", response_model=DashboardSummary)
def project_dashboard(project_id: str, db: DbSession, current_user: CurrentUser) -> DashboardSummary:
    project = get_owned_project(project_id, db, current_user)
    sync_project_risk(db, project)
    db.commit()
    db.refresh(project)

    total_assets = db.scalar(select(func.count(Asset.id)).where(Asset.project_id == project.id)) or 0
    active_assets = (
        db.scalar(select(func.count(Asset.id)).where(Asset.project_id == project.id, Asset.status == "active")) or 0
    )
    open_ports = db.scalar(select(func.count(Port.id)).where(Port.project_id == project.id, Port.status == "open")) or 0
    critical_high = (
        db.scalar(
            select(func.count(Finding.id)).where(
                Finding.project_id == project.id,
                Finding.status == "open",
                Finding.severity.in_(["critical", "high"]),
            )
        )
        or 0
    )
    expiring = (
        db.scalar(select(func.count(SslResult.id)).where(SslResult.project_id == project.id, SslResult.status == "expiring_soon"))
        or 0
    )
    missing_headers = (
        db.scalar(
            select(func.count(SecurityHeader.id)).where(
                SecurityHeader.project_id == project.id,
                SecurityHeader.present.is_(False),
            )
        )
        or 0
    )
    severity_rows = db.execute(
        select(Finding.severity, func.count(Finding.id)).where(Finding.project_id == project.id).group_by(Finding.severity)
    ).all()
    recent_changes = [
        {
            "id": change.id,
            "change_type": change.change_type,
            "severity": change.severity,
            "old_value": change.old_value,
            "new_value": change.new_value,
            "detected_at": change.detected_at.isoformat(),
        }
        for change in db.scalars(
            select(Change).where(Change.project_id == project.id).order_by(Change.detected_at.desc()).limit(8)
        )
    ]
    recent_scans = [
        {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "risk_score": scan.risk_score,
            "findings_created": scan.findings_created,
        }
        for scan in db.scalars(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()).limit(5))
    ]

    return DashboardSummary(
        project=ProjectRead.model_validate(project),
        total_assets=total_assets,
        active_subdomains=active_assets,
        open_ports=open_ports,
        critical_high_findings=critical_high,
        expiring_certificates=expiring,
        missing_security_headers=missing_headers,
        recent_changes=recent_changes,
        recent_scans=recent_scans,
        severity_counts={severity: count for severity, count in severity_rows},
    )
