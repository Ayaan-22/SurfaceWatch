"""initial surfacewatch schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-01
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)

    op.create_table(
        "projects",
        sa.Column("owner_id", sa.String(), nullable=False),
        sa.Column("company_name", sa.String(length=255), nullable=False),
        sa.Column("main_domain", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("scan_frequency", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("risk_status", sa.String(length=32), nullable=False),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_projects_id"), "projects", ["id"], unique=False)
    op.create_index(op.f("ix_projects_main_domain"), "projects", ["main_domain"], unique=False)
    op.create_index(op.f("ix_projects_owner_id"), "projects", ["owner_id"], unique=False)

    op.create_table(
        "scans",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("assets_scanned", sa.Integer(), nullable=False),
        sa.Column("findings_created", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_id"), "scans", ["id"], unique=False)
    op.create_index(op.f("ix_scans_project_id"), "scans", ["project_id"], unique=False)

    op.create_table(
        "assets",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("dns_record_type", sa.String(length=32), nullable=True),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "hostname", name="uq_asset_project_hostname"),
    )
    op.create_index(op.f("ix_assets_hostname"), "assets", ["hostname"], unique=False)
    op.create_index(op.f("ix_assets_id"), "assets", ["id"], unique=False)
    op.create_index(op.f("ix_assets_project_id"), "assets", ["project_id"], unique=False)
    op.create_index(op.f("ix_assets_scan_id"), "assets", ["scan_id"], unique=False)

    op.create_table(
        "changes",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("change_type", sa.String(length=128), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_changes_id"), "changes", ["id"], unique=False)
    op.create_index(op.f("ix_changes_project_id"), "changes", ["project_id"], unique=False)
    op.create_index(op.f("ix_changes_scan_id"), "changes", ["scan_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("business_impact", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_category"), "findings", ["category"], unique=False)
    op.create_index(op.f("ix_findings_id"), "findings", ["id"], unique=False)
    op.create_index(op.f("ix_findings_project_id"), "findings", ["project_id"], unique=False)
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)

    op.create_table(
        "notifications",
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("notification_type", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("is_read", sa.Boolean(), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_notifications_id"), "notifications", ["id"], unique=False)
    op.create_index(op.f("ix_notifications_project_id"), "notifications", ["project_id"], unique=False)
    op.create_index(op.f("ix_notifications_user_id"), "notifications", ["user_id"], unique=False)

    op.create_table(
        "ports",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("service_guess", sa.String(length=128), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "port", "protocol", name="uq_port_asset_port_protocol"),
    )
    op.create_index(op.f("ix_ports_asset_id"), "ports", ["asset_id"], unique=False)
    op.create_index(op.f("ix_ports_id"), "ports", ["id"], unique=False)
    op.create_index(op.f("ix_ports_project_id"), "ports", ["project_id"], unique=False)
    op.create_index(op.f("ix_ports_scan_id"), "ports", ["scan_id"], unique=False)

    op.create_table(
        "reports",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_reports_id"), "reports", ["id"], unique=False)
    op.create_index(op.f("ix_reports_project_id"), "reports", ["project_id"], unique=False)

    op.create_table(
        "scan_logs",
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_logs_id"), "scan_logs", ["id"], unique=False)
    op.create_index(op.f("ix_scan_logs_scan_id"), "scan_logs", ["scan_id"], unique=False)

    op.create_table(
        "security_headers",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("header_name", sa.String(length=128), nullable=False),
        sa.Column("present", sa.Boolean(), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("risk_level", sa.String(length=32), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "header_name", name="uq_header_asset_name"),
    )
    op.create_index(op.f("ix_security_headers_asset_id"), "security_headers", ["asset_id"], unique=False)
    op.create_index(op.f("ix_security_headers_id"), "security_headers", ["id"], unique=False)
    op.create_index(op.f("ix_security_headers_project_id"), "security_headers", ["project_id"], unique=False)
    op.create_index(op.f("ix_security_headers_scan_id"), "security_headers", ["scan_id"], unique=False)

    op.create_table(
        "ssl_results",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=True),
        sa.Column("subject_common_name", sa.String(length=255), nullable=True),
        sa.Column("subject_alt_names", sa.JSON(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("days_until_expiry", sa.Integer(), nullable=True),
        sa.Column("expired", sa.Boolean(), nullable=True),
        sa.Column("self_signed", sa.Boolean(), nullable=True),
        sa.Column("tls_versions", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ssl_results_asset_id"), "ssl_results", ["asset_id"], unique=False)
    op.create_index(op.f("ix_ssl_results_id"), "ssl_results", ["id"], unique=False)
    op.create_index(op.f("ix_ssl_results_project_id"), "ssl_results", ["project_id"], unique=False)
    op.create_index(op.f("ix_ssl_results_scan_id"), "ssl_results", ["scan_id"], unique=False)

    op.create_table(
        "technologies",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "name", "evidence", name="uq_tech_asset_name_evidence"),
    )
    op.create_index(op.f("ix_technologies_asset_id"), "technologies", ["asset_id"], unique=False)
    op.create_index(op.f("ix_technologies_id"), "technologies", ["id"], unique=False)
    op.create_index(op.f("ix_technologies_project_id"), "technologies", ["project_id"], unique=False)
    op.create_index(op.f("ix_technologies_scan_id"), "technologies", ["scan_id"], unique=False)


def downgrade() -> None:
    for table in (
        "technologies",
        "ssl_results",
        "security_headers",
        "scan_logs",
        "reports",
        "ports",
        "notifications",
        "findings",
        "changes",
        "assets",
        "scans",
        "projects",
        "users",
    ):
        op.drop_table(table)
