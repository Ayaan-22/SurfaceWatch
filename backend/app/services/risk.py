from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, Project
from app.scanner.risk_engine import calculate_risk_score


def calculate_open_finding_risk(db: Session, project_id: str) -> tuple[int, str]:
    db.flush()
    severities = list(
        db.scalars(
            select(Finding.severity).where(
                Finding.project_id == project_id,
                Finding.status == "open",
            )
        )
    )
    score, level, _ = calculate_risk_score(severities)
    return score, level


def sync_project_risk(db: Session, project: Project) -> tuple[int, str]:
    score, level = calculate_open_finding_risk(db, project.id)
    project.risk_score = score
    project.risk_level = level
    project.risk_status = "attention_required" if score > 50 else "monitored"
    return score, level
