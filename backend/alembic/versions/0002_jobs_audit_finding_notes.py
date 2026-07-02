"""add jobs audit and finding notes

Revision ID: 0002_jobs_audit_notes
Revises: 0001_initial
Create Date: 2026-07-02
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_jobs_audit_notes"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=True),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
    op.create_index(op.f("ix_audit_logs_id"), "audit_logs", ["id"], unique=False)
    op.create_index(op.f("ix_audit_logs_resource_id"), "audit_logs", ["resource_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_user_id"), "audit_logs", ["user_id"], unique=False)

    op.create_table(
        "scheduled_jobs",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("job_type", sa.String(length=64), nullable=False),
        sa.Column("frequency", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scheduled_jobs_id"), "scheduled_jobs", ["id"], unique=False)
    op.create_index(op.f("ix_scheduled_jobs_next_run_at"), "scheduled_jobs", ["next_run_at"], unique=False)
    op.create_index(op.f("ix_scheduled_jobs_project_id"), "scheduled_jobs", ["project_id"], unique=False)

    op.create_table(
        "finding_notes",
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_finding_notes_finding_id"), "finding_notes", ["finding_id"], unique=False)
    op.create_index(op.f("ix_finding_notes_id"), "finding_notes", ["id"], unique=False)
    op.create_index(op.f("ix_finding_notes_user_id"), "finding_notes", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_table("finding_notes")
    op.drop_table("scheduled_jobs")
    op.drop_table("audit_logs")
