from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


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
    assets_discovered: int = 0
    assets_failed: int = 0
    checks_completed: int = 0
    checks_failed: int = 0
    coverage_percent: int = 0
    attempt_count: int = 0
    heartbeat_at: datetime | None = None
    findings_created: int
    risk_score: int
    error_message: str | None = None
    partial_reason: str | None = None
    discovery_metadata: dict[str, Any] | list[Any] | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanAssetResultRead(BaseModel):
    id: str
    project_id: str
    scan_id: str
    asset_id: str | None = None
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    source: str | None = None
    discovery_status: str
    scan_status: str = "pending"
    risk_level: str = "unknown"
    checks: dict[str, Any] = Field(default_factory=dict)
    http_observations: list[Any] = Field(default_factory=list)
    tls_observations: list[Any] = Field(default_factory=list)
    port_observations: list[Any] = Field(default_factory=list)
    header_observations: list[Any] = Field(default_factory=list)
    technology_observations: list[Any] = Field(default_factory=list)
    exposure_observations: list[Any] = Field(default_factory=list)
    finding_observations: list[Any] = Field(default_factory=list)
    errors: list[Any] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ScanLogRead(BaseModel):
    id: str
    level: str
    message: str
    created_at: datetime

    model_config = {"from_attributes": True}
