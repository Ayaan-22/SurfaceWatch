from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Project(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "projects"

    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    company_name: Mapped[str] = mapped_column(String(255), nullable=False)
    main_domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_contact: Mapped[str | None] = mapped_column(String(255))
    authorization_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_scan_profile: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    scan_frequency: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="low", nullable=False)
    risk_status: Mapped[str] = mapped_column(String(32), default="not_scanned", nullable=False)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner = relationship("User", back_populates="projects")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    changes = relationship("Change", back_populates="project", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="project", cascade="all, delete-orphan")
    scheduled_jobs = relationship("ScheduledJob", back_populates="project", cascade="all, delete-orphan")
