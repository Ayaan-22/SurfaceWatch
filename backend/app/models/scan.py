from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Scan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    scan_profile: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    assets_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)

    project = relationship("Project", back_populates="scans")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")


class ScanLog(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scan_logs"

    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(16), default="info", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan = relationship("Scan", back_populates="logs")
