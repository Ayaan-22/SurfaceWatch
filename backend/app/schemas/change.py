from datetime import datetime

from pydantic import BaseModel


class ChangeRead(BaseModel):
    id: str
    project_id: str
    scan_id: str | None = None
    asset_id: str | None = None
    change_type: str
    old_value: str | None = None
    new_value: str | None = None
    severity: str
    detected_at: datetime

    model_config = {"from_attributes": True}
