from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Asset(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "hostname", name="uq_asset_project_hostname"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), default="subdomain", nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    dns_record_type: Mapped[str | None] = mapped_column(String(32))
    source: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    project = relationship("Project", back_populates="assets")
    scan = relationship("Scan", back_populates="assets")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    ssl_results = relationship("SslResult", back_populates="asset", cascade="all, delete-orphan")
    security_headers = relationship("SecurityHeader", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship("Technology", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset")
    scan_results = relationship("ScanAssetResult", back_populates="asset")


class Port(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_port_asset_port_protocol"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    service_guess: Mapped[str | None] = mapped_column(String(128))
    banner: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset = relationship("Asset", back_populates="ports")


class SslResult(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ssl_results"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    issuer: Mapped[str | None] = mapped_column(String(512))
    subject_common_name: Mapped[str | None] = mapped_column(String(255))
    subject_alt_names: Mapped[list[str] | None] = mapped_column(JSON)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    days_until_expiry: Mapped[int | None] = mapped_column(Integer)
    expired: Mapped[bool | None] = mapped_column()
    self_signed: Mapped[bool | None] = mapped_column()
    tls_versions: Mapped[list[str] | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    error: Mapped[str | None] = mapped_column(Text)

    asset = relationship("Asset", back_populates="ssl_results")


class SecurityHeader(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "security_headers"
    __table_args__ = (UniqueConstraint("asset_id", "header_name", name="uq_header_asset_name"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    header_name: Mapped[str] = mapped_column(String(128), nullable=False)
    present: Mapped[bool] = mapped_column(default=False, nullable=False)
    value: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(32), default="info", nullable=False)

    asset = relationship("Asset", back_populates="security_headers")


class Technology(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "technologies"
    __table_args__ = (UniqueConstraint("asset_id", "name", "evidence", name="uq_tech_asset_name_evidence"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset = relationship("Asset", back_populates="technologies")
