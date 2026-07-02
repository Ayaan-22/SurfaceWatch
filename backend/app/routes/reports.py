from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.models import Report
from app.reports.builder import build_excel_report, build_pdf_report
from app.routes.deps import CurrentUser, DbSession, get_owned_project
from app.schemas.report import ReportRead

router = APIRouter(tags=["reports"])


@router.post("/projects/{project_id}/reports/pdf", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
def create_pdf_report(project_id: str, db: DbSession, current_user: CurrentUser) -> Report:
    project = get_owned_project(project_id, db, current_user)
    report = Report(project_id=project.id, report_type="pdf", status="pending")
    db.add(report)
    db.flush()
    try:
        path = build_pdf_report(db, project, report)
        report.file_path = str(path)
        report.status = "ready"
    except Exception as exc:
        report.status = "failed"
        report.error_message = str(exc)
    db.commit()
    db.refresh(report)
    return report


@router.post("/projects/{project_id}/reports/excel", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
def create_excel_report(project_id: str, db: DbSession, current_user: CurrentUser) -> Report:
    project = get_owned_project(project_id, db, current_user)
    report = Report(project_id=project.id, report_type="excel", status="pending")
    db.add(report)
    db.flush()
    try:
        path = build_excel_report(db, project, report)
        report.file_path = str(path)
        report.status = "ready"
    except Exception as exc:
        report.status = "failed"
        report.error_message = str(exc)
    db.commit()
    db.refresh(report)
    return report


@router.get("/projects/{project_id}/reports", response_model=list[ReportRead])
def list_reports(project_id: str, db: DbSession, current_user: CurrentUser) -> list[Report]:
    project = get_owned_project(project_id, db, current_user)
    return list(db.scalars(select(Report).where(Report.project_id == project.id).order_by(Report.created_at.desc())))


@router.get("/reports/{report_id}/download")
def download_report(report_id: str, db: DbSession, current_user: CurrentUser) -> FileResponse:
    report = db.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    get_owned_project(report.project_id, db, current_user)
    if report.status != "ready" or not report.file_path:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Report is not ready.")
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file is missing.")
    media_type = "application/pdf" if report.report_type == "pdf" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(path, media_type=media_type, filename=path.name)
