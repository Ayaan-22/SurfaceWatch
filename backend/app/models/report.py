from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Report(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    report_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    file_path: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    project = relationship("Project", back_populates="reports")
    scan = relationship("Scan", back_populates="reports")

    @property
    def scan_profile(self) -> str | None:
        return self.scan.scan_profile if self.scan is not None else None

    @property
    def scan_date(self):
        if self.scan is None:
            return None
        return self.scan.finished_at or self.scan.started_at or self.scan.created_at
