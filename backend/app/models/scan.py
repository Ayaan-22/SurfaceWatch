from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Scan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index(
            "uq_scans_one_active_per_project",
            "project_id",
            unique=True,
            sqlite_where=text("status IN ('queued','pending','claimed','running')"),
            postgresql_where=text("status IN ('queued','pending','claimed','running')"),
        ),
    )

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    assets_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    assets_failed: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    checks_completed: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    checks_failed: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    coverage_percent: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    worker_token: Mapped[str | None] = mapped_column(String(64))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    findings_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    partial_reason: Mapped[str | None] = mapped_column(Text)
    discovery_metadata: Mapped[dict | list | None] = mapped_column(JSON)

    project = relationship("Project", back_populates="scans")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")
    reports = relationship("Report", back_populates="scan")
    asset_results = relationship("ScanAssetResult", back_populates="scan", cascade="all, delete-orphan")


class ScanAssetResult(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scan_asset_results"
    __table_args__ = (UniqueConstraint("scan_id", "hostname", name="uq_scan_asset_result_scan_hostname"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_addresses: Mapped[list[str]] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    source: Mapped[str | None] = mapped_column(String(128))
    discovery_status: Mapped[str] = mapped_column(String(32), nullable=False)
    scan_status: Mapped[str] = mapped_column(String(32), default="pending", server_default="pending", nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown", nullable=False)
    checks: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}", nullable=False)
    http_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    tls_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    port_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    header_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    technology_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    exposure_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    finding_observations: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    errors: Mapped[list] = mapped_column(JSON, default=list, server_default="[]", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan = relationship("Scan", back_populates="asset_results")
    asset = relationship("Asset", back_populates="scan_results")


class ScanLog(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scan_logs"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan = relationship("Scan", back_populates="logs")
