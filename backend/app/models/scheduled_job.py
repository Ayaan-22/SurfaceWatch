from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class ScheduledJob(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scheduled_jobs"
    __table_args__ = (UniqueConstraint("project_id", "job_type", name="uq_scheduled_job_project_type"),)

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    job_type: Mapped[str] = mapped_column(String(64), default="scan", nullable=False)
    frequency: Mapped[str] = mapped_column(String(32), default="manual", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project = relationship("Project", back_populates="scheduled_jobs")
