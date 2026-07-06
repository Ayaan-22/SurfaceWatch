from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.utils.domain_validation import normalize_domain


class ProjectBase(BaseModel):
    company_name: str = Field(min_length=2, max_length=255)
    main_domain: str = Field(min_length=4, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    scan_frequency: str = Field(default="manual", pattern="^(manual|daily|weekly|monthly)$")

    @field_validator("main_domain")
    @classmethod
    def normalize_main_domain(cls, value: str) -> str:
        return normalize_domain(value)


class ProjectCreate(ProjectBase):
    authorization_confirmed: bool
    authorization_contact: str | None = Field(default=None, min_length=3, max_length=255)
    authorization_expires_at: datetime | None = None
    max_scan_profile: Literal["safe", "aggressive"] = "safe"


class ProjectUpdate(BaseModel):
    company_name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    scan_frequency: str | None = Field(default=None, pattern="^(manual|daily|weekly|monthly)$")
    authorization_confirmed: bool | None = None
    authorization_contact: str | None = Field(default=None, min_length=3, max_length=255)
    authorization_expires_at: datetime | None = None
    max_scan_profile: Literal["safe", "aggressive"] | None = None


class ProjectRead(ProjectBase):
    id: str
    authorization_confirmed: bool
    authorization_contact: str | None = None
    authorization_expires_at: datetime | None = None
    max_scan_profile: str
    risk_score: int
    risk_level: str
    risk_status: str
    created_at: datetime
    updated_at: datetime
    last_scan_at: datetime | None = None
    next_scan_at: datetime | None = None

    model_config = {"from_attributes": True}


class DashboardSummary(BaseModel):
    project: ProjectRead
    total_assets: int
    active_subdomains: int
    open_ports: int
    critical_high_findings: int
    expiring_certificates: int
    missing_security_headers: int
    recent_changes: list[dict]
    recent_scans: list[dict]
    severity_counts: dict[str, int]
