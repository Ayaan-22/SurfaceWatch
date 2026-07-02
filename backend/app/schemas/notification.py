from datetime import datetime
from typing import Any

from pydantic import BaseModel


class NotificationRead(BaseModel):
    id: str
    project_id: str | None = None
    title: str
    message: str
    notification_type: str
    metadata_json: dict[str, Any] | None = None
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}
