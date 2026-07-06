"""add scan profile

Revision ID: 0003_scan_profile
Revises: 0002_jobs_audit_notes
Create Date: 2026-07-02
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_scan_profile"
down_revision = "0002_jobs_audit_notes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "scan_profile" not in columns:
        op.add_column("scans", sa.Column("scan_profile", sa.String(length=32), nullable=False, server_default="safe"))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("scan_profile")
