from datetime import datetime

from pydantic import BaseModel, Field


class ScheduledJobRead(BaseModel):
    id: str
    project_id: str
    job_type: str
    frequency: str
    status: str
    next_run_at: datetime | None = None
    last_run_at: datetime | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScheduledJobUpdate(BaseModel):
    frequency: str = Field(pattern="^(manual|daily|weekly|monthly)$")
    status: str = Field(default="active", pattern="^(active|paused)$")
