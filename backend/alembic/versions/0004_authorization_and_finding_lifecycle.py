"""add authorization evidence and finding lifecycle metadata

Revision ID: 0004_auth_finding_lifecycle
Revises: 0003_scan_profile
Create Date: 2026-07-03
"""

from alembic import op
import sqlalchemy as sa
from datetime import datetime, timedelta, timezone


revision = "0004_auth_finding_lifecycle"
down_revision = "0003_scan_profile"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    project_columns = _columns("projects")
    with op.batch_alter_table("projects") as batch_op:
        if "authorization_contact" not in project_columns:
            batch_op.add_column(sa.Column("authorization_contact", sa.String(length=255), nullable=True))
        if "authorization_expires_at" not in project_columns:
            batch_op.add_column(sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=True))
        if "max_scan_profile" not in project_columns:
            batch_op.add_column(sa.Column("max_scan_profile", sa.String(length=32), nullable=False, server_default="safe"))

    legacy_expiry = datetime.now(timezone.utc) + timedelta(days=365)
    op.execute(
        sa.text(
            """
            UPDATE projects
            SET authorization_contact = COALESCE(authorization_contact, :contact),
                authorization_expires_at = COALESCE(authorization_expires_at, :expires_at),
                max_scan_profile = COALESCE(max_scan_profile, 'safe')
            WHERE authorization_confirmed = 1
            """
        ).bindparams(contact="legacy-upgrade@surfacewatch.local", expires_at=legacy_expiry)
    )

    finding_columns = _columns("findings")
    with op.batch_alter_table("findings") as batch_op:
        if "fingerprint" not in finding_columns:
            batch_op.add_column(sa.Column("fingerprint", sa.String(length=64), nullable=True))
        if "confidence" not in finding_columns:
            batch_op.add_column(sa.Column("confidence", sa.String(length=32), nullable=False, server_default="medium"))
        if "cvss_score" not in finding_columns:
            batch_op.add_column(sa.Column("cvss_score", sa.Float(), nullable=True))
        if "evidence_hash" not in finding_columns:
            batch_op.add_column(sa.Column("evidence_hash", sa.String(length=64), nullable=True))
        if "sla_due_at" not in finding_columns:
            batch_op.add_column(sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True))
        if "owner" not in finding_columns:
            batch_op.add_column(sa.Column("owner", sa.String(length=255), nullable=True))

    op.create_index(op.f("ix_findings_fingerprint"), "findings", ["fingerprint"], unique=False)
    op.create_index(op.f("ix_findings_evidence_hash"), "findings", ["evidence_hash"], unique=False)
    op.create_index(op.f("ix_findings_sla_due_at"), "findings", ["sla_due_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_sla_due_at"), table_name="findings")
    op.drop_index(op.f("ix_findings_evidence_hash"), table_name="findings")
    op.drop_index(op.f("ix_findings_fingerprint"), table_name="findings")
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("owner")
        batch_op.drop_column("sla_due_at")
        batch_op.drop_column("evidence_hash")
        batch_op.drop_column("cvss_score")
        batch_op.drop_column("confidence")
        batch_op.drop_column("fingerprint")
    with op.batch_alter_table("projects") as batch_op:
        batch_op.drop_column("max_scan_profile")
        batch_op.drop_column("authorization_expires_at")
        batch_op.drop_column("authorization_contact")
