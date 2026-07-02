from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FindingRead(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    category: str
    evidence: Any = None
    business_impact: str | None = None
    recommendation: str | None = None
    status: str
    notes: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    asset_id: str | None = None

    model_config = {"from_attributes": True}


class FindingNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class FindingNoteRead(BaseModel):
    id: str
    finding_id: str
    user_id: str | None = None
    note: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|accepted_risk|fixed|false_positive)$")
    notes: str | None = Field(default=None, max_length=2000)
