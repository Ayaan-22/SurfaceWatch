from datetime import datetime

from pydantic import BaseModel


class ReportRead(BaseModel):
    id: str
    project_id: str
    scan_id: str | None = None
    report_type: str
    status: str
    file_path: str | None = None
    error_message: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
