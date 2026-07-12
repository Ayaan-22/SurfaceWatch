"""add immutable per-scan asset results and scan telemetry

Revision ID: 0005_scan_asset_results
Revises: 0004_auth_finding_lifecycle
Create Date: 2026-07-10
"""

from alembic import op
import sqlalchemy as sa


revision = "0005_scan_asset_results"
down_revision = "0004_auth_finding_lifecycle"
branch_labels = None
depends_on = None


def _columns(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    scan_columns = _columns("scans")
    with op.batch_alter_table("scans") as batch_op:
        if "assets_discovered" not in scan_columns:
            batch_op.add_column(sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "assets_failed" not in scan_columns:
            batch_op.add_column(sa.Column("assets_failed", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "checks_completed" not in scan_columns:
            batch_op.add_column(sa.Column("checks_completed", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "checks_failed" not in scan_columns:
            batch_op.add_column(sa.Column("checks_failed", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "coverage_percent" not in scan_columns:
            batch_op.add_column(sa.Column("coverage_percent", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "attempt_count" not in scan_columns:
            batch_op.add_column(sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")))
        if "worker_token" not in scan_columns:
            batch_op.add_column(sa.Column("worker_token", sa.String(length=64), nullable=True))
        if "heartbeat_at" not in scan_columns:
            batch_op.add_column(sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
        if "partial_reason" not in scan_columns:
            batch_op.add_column(sa.Column("partial_reason", sa.Text(), nullable=True))
        if "discovery_metadata" not in scan_columns:
            batch_op.add_column(sa.Column("discovery_metadata", sa.JSON(), nullable=True))

    inspector = sa.inspect(op.get_bind())
    scan_indexes = {index["name"] for index in inspector.get_indexes("scans")}
    if "uq_scans_one_active_per_project" not in scan_indexes:
        op.execute(
            sa.text(
                "UPDATE scans SET status = 'failed', "
                "error_message = 'Superseded duplicate active scan during migration', "
                "partial_reason = 'Superseded duplicate active scan during migration', "
                "finished_at = CURRENT_TIMESTAMP "
                "WHERE status IN ('queued','pending','claimed','running') AND id NOT IN "
                "(SELECT MIN(id) FROM scans WHERE status IN ('queued','pending','claimed','running') GROUP BY project_id)"
            )
        )
        op.create_index(
            "uq_scans_one_active_per_project",
            "scans",
            ["project_id"],
            unique=True,
            sqlite_where=sa.text("status IN ('queued','pending','claimed','running')"),
            postgresql_where=sa.text("status IN ('queued','pending','claimed','running')"),
        )

    inspector = sa.inspect(op.get_bind())
    scheduled_uniques = {constraint["name"] for constraint in inspector.get_unique_constraints("scheduled_jobs")}
    if "uq_scheduled_job_project_type" not in scheduled_uniques:
        op.execute(
            sa.text(
                "DELETE FROM scheduled_jobs WHERE id NOT IN "
                "(SELECT MIN(id) FROM scheduled_jobs GROUP BY project_id, job_type)"
            )
        )
        with op.batch_alter_table("scheduled_jobs") as batch_op:
            batch_op.create_unique_constraint("uq_scheduled_job_project_type", ["project_id", "job_type"])

    inspector = sa.inspect(op.get_bind())
    if "scan_asset_results" in inspector.get_table_names():
        return

    op.create_table(
        "scan_asset_results",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_addresses", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column("discovery_status", sa.String(length=32), nullable=False),
        sa.Column("scan_status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("risk_level", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("checks", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("http_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("tls_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("port_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("header_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("technology_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("exposure_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("finding_observations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("errors", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "hostname", name="uq_scan_asset_result_scan_hostname"),
    )
    op.create_index(op.f("ix_scan_asset_results_asset_id"), "scan_asset_results", ["asset_id"], unique=False)
    op.create_index(op.f("ix_scan_asset_results_hostname"), "scan_asset_results", ["hostname"], unique=False)
    op.create_index(op.f("ix_scan_asset_results_id"), "scan_asset_results", ["id"], unique=False)
    op.create_index(op.f("ix_scan_asset_results_project_id"), "scan_asset_results", ["project_id"], unique=False)
    op.create_index(op.f("ix_scan_asset_results_scan_id"), "scan_asset_results", ["scan_id"], unique=False)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "scan_asset_results" in inspector.get_table_names():
        op.drop_table("scan_asset_results")

    scheduled_uniques = {constraint["name"] for constraint in inspector.get_unique_constraints("scheduled_jobs")}
    if "uq_scheduled_job_project_type" in scheduled_uniques:
        with op.batch_alter_table("scheduled_jobs") as batch_op:
            batch_op.drop_constraint("uq_scheduled_job_project_type", type_="unique")

    scan_indexes = {index["name"] for index in inspector.get_indexes("scans")}
    if "uq_scans_one_active_per_project" in scan_indexes:
        op.drop_index("uq_scans_one_active_per_project", table_name="scans")

    scan_columns = _columns("scans")
    with op.batch_alter_table("scans") as batch_op:
        if "discovery_metadata" in scan_columns:
            batch_op.drop_column("discovery_metadata")
        if "partial_reason" in scan_columns:
            batch_op.drop_column("partial_reason")
        if "coverage_percent" in scan_columns:
            batch_op.drop_column("coverage_percent")
        if "heartbeat_at" in scan_columns:
            batch_op.drop_column("heartbeat_at")
        if "worker_token" in scan_columns:
            batch_op.drop_column("worker_token")
        if "attempt_count" in scan_columns:
            batch_op.drop_column("attempt_count")
        if "checks_failed" in scan_columns:
            batch_op.drop_column("checks_failed")
        if "checks_completed" in scan_columns:
            batch_op.drop_column("checks_completed")
        if "assets_failed" in scan_columns:
            batch_op.drop_column("assets_failed")
        if "assets_discovered" in scan_columns:
            batch_op.drop_column("assets_discovered")
