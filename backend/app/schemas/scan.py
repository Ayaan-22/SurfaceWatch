from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ScanStartRequest(BaseModel):
    scan_profile: Literal["safe", "aggressive"] = "safe"


class ScanRead(BaseModel):
    id: str
    project_id: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    status: str
    trigger: str
    scan_profile: str
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
