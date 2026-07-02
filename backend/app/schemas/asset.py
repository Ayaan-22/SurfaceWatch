from datetime import datetime

from pydantic import BaseModel


class PortRead(BaseModel):
    id: str
    port: int
    protocol: str
    status: str
    service_guess: str | None = None
    banner: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class TechnologyRead(BaseModel):
    id: str
    name: str
    category: str
    confidence: int
    evidence: str
    first_seen_at: datetime
    last_seen_at: datetime

    model_config = {"from_attributes": True}


class AssetRead(BaseModel):
    id: str
    hostname: str
    asset_type: str
    ip_address: str | None = None
    dns_record_type: str | None = None
    source: str | None = None
    status: str
    risk_level: str
    first_seen_at: datetime
    last_seen_at: datetime
    ports: list[PortRead] = []
    technologies: list[TechnologyRead] = []

    model_config = {"from_attributes": True}
