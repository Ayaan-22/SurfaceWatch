from datetime import datetime

from pydantic import BaseModel


class ScanRead(BaseModel):
    id: str
    project_id: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str
    trigger: str
    assets_scanned: int
    findings_created: int
    risk_score: int
    error_message: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanLogRead(BaseModel):
    id: str
    level: str
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}
