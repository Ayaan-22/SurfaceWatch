from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.mixins import TimestampMixin, UUIDMixin


class Finding(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "findings"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    confidence: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    evidence_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    owner: Mapped[str | None] = mapped_column(String(255))
    evidence: Mapped[dict | list | str | None] = mapped_column(JSON)
    business_impact: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    project = relationship("Project", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    note_entries = relationship("FindingNote", back_populates="finding", cascade="all, delete-orphan")

    @property
    def asset_hostname(self) -> str | None:
        return self.asset.hostname if self.asset is not None else None


class FindingNote(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "finding_notes"

    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    note: Mapped[str] = mapped_column(Text, nullable=False)

    finding = relationship("Finding", back_populates="note_entries")


class Change(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "changes"

    project_id: Mapped[str] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_id: Mapped[str | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    change_type: Mapped[str] = mapped_column(String(128), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(32), default="info", nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    project = relationship("Project", back_populates="changes")
