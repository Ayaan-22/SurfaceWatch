from datetime import timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.config import get_settings
from app.database import Base
from app.models import Asset, Finding, Notification, Project, Scan, ScanAssetResult, SslResult, User
from app.models.mixins import utc_now
from app.scanner import orchestrator
from app.scanner.orchestrator import AssetNetworkResult
from app.scanner.ports import PortCheckResult
from app.scanner.ssl_checker import SslCheckResult
from app.scanner.subdomains import DiscoveryResult, DiscoverySourceStatus, SubdomainCandidate


def _session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return factory()


def _project_and_scan(db: Session, *, domain: str = "example.org") -> tuple[Project, Scan]:
    now = utc_now()
    user = User(email=f"owner-{domain}@example.org", full_name="Scan Owner", hashed_password="hash")
    project = Project(
        owner=user,
        company_name="Completeness Org",
        main_domain=domain,
        authorization_confirmed=True,
        authorization_contact="security@example.org",
        authorization_expires_at=now + timedelta(days=30),
        max_scan_profile="aggressive",
    )
    scan = Scan(project=project, status="queued", scan_profile="safe")
    db.add_all([user, project, scan])
    db.commit()
    return project, scan


def _discovery(domain: str, *, source_failed: bool = False) -> DiscoveryResult:
    source_status = "failed" if source_failed else "completed"
    return DiscoveryResult(
        candidates=[
            SubdomainCandidate(
                hostname=domain,
                ip_addresses=["93.184.216.34"],
                source="passive_seed_dns",
                status="active",
            )
        ],
        sources={
            "crtsh": DiscoverySourceStatus(source_status, 0, 1, "provider unavailable" if source_failed else None),
            "certspotter": DiscoverySourceStatus("completed", 0, 1),
            "hostsearch": DiscoverySourceStatus("completed", 0, 1),
            "rapiddns": DiscoverySourceStatus("completed", 0, 1),
            "dns_resolution": DiscoverySourceStatus("completed", 1, 1),
        },
        total_candidates=1,
        truncated=False,
        aggressive_dns_enabled=False,
    )


def _healthy_tls() -> SslCheckResult:
    return SslCheckResult(
        issuer="CN=Trusted CA",
        subject_common_name="example.org",
        subject_alt_names=["example.org"],
        valid_from=utc_now() - timedelta(days=10),
        valid_until=utc_now() + timedelta(days=90),
        days_until_expiry=90,
        expired=False,
        self_signed=False,
        status="healthy",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        certificate_verified=True,
    )


def _network_result(domain: str, *, failed_http: bool = False, open_port: int | None = None) -> AssetNetworkResult:
    ports = []
    if open_port is not None:
        ports.append(PortCheckResult(open_port, "tcp", "open", "node-dev"))
    checks = {
        "dns": {"status": "completed", "planned": 1, "completed": 1},
        "ports": {"status": "completed", "planned": len(ports), "completed": len(ports)},
        "http": {
            "status": "failed" if failed_http else "completed",
            "planned": 1,
            "completed": 0 if failed_http else 1,
            **({"error": "probe crashed"} if failed_http else {}),
        },
        "tls": {"status": "completed", "planned": 1, "completed": 1},
    }
    return AssetNetworkResult(
        hostname=domain,
        resolved_ips=["93.184.216.34"],
        http_results=[],
        ssl_result=_healthy_tls(),
        port_results=ports,
        exposure_results=[],
        checks=checks,
        errors=[{"stage": "http", "error": "probe crashed"}] if failed_http else [],
    )


def _patch_scan(monkeypatch, domain: str, network: AssetNetworkResult, *, source_failed: bool = False) -> None:
    settings = get_settings().model_copy(
        update={
            "scan_concurrency": 1,
            "max_scan_duration_seconds": 30,
            "default_ports": [3000],
        }
    )
    monkeypatch.setattr(orchestrator, "get_settings", lambda: settings)
    monkeypatch.setattr(orchestrator, "discover_subdomains", lambda *args, **kwargs: _discovery(domain, source_failed=source_failed))
    monkeypatch.setattr(orchestrator, "_scan_asset_network", lambda *args, **kwargs: network)


def test_partial_module_failure_preserves_successful_results(monkeypatch) -> None:
    db = _session()
    try:
        project, scan = _project_and_scan(db)
        _patch_scan(monkeypatch, project.main_domain, _network_result(project.main_domain, failed_http=True, open_port=3000))

        orchestrator.run_project_scan(scan.id, db)

        db.refresh(scan)
        manifest = db.scalar(select(ScanAssetResult).where(ScanAssetResult.scan_id == scan.id))
        assert manifest is not None
        assert scan.status == "partial"
        assert scan.coverage_percent == 75
        assert scan.checks_completed == 3
        assert scan.checks_failed == 1
        assert manifest.scan_status == "partial"
        assert manifest.port_observations[0]["port"] == 3000
        assert [finding["title"] for finding in manifest.finding_observations] == ["Development port exposed"]
        assert manifest.errors == [{"stage": "http", "error": "probe crashed"}]
    finally:
        db.close()


def test_rescan_does_not_change_previous_scan_manifest_and_executes_once(monkeypatch) -> None:
    db = _session()
    try:
        project, first_scan = _project_and_scan(db)
        _patch_scan(monkeypatch, project.main_domain, _network_result(project.main_domain, open_port=3000))
        orchestrator.run_project_scan(first_scan.id, db)

        first_manifest = db.scalar(select(ScanAssetResult).where(ScanAssetResult.scan_id == first_scan.id))
        assert first_manifest is not None
        first_snapshot = list(first_manifest.finding_observations)

        second_scan = Scan(project_id=project.id, status="queued", scan_profile="safe")
        db.add(second_scan)
        db.commit()
        orchestrator.run_project_scan(second_scan.id, db)
        orchestrator.run_project_scan(second_scan.id, db)  # Terminal scans are idempotent.

        db.refresh(first_manifest)
        assert first_manifest.finding_observations == first_snapshot
        assert db.scalar(select(func.count()).select_from(ScanAssetResult).where(ScanAssetResult.scan_id == first_scan.id)) == 1
        assert db.scalar(select(func.count()).select_from(ScanAssetResult).where(ScanAssetResult.scan_id == second_scan.id)) == 1
        assert db.scalar(select(func.count()).select_from(SslResult).where(SslResult.scan_id == second_scan.id)) == 1
        assert db.scalar(
            select(func.count()).select_from(Notification).where(
                Notification.notification_type == "scan_completed",
                Notification.project_id == project.id,
            )
        ) == 2

        canonical_findings = list(db.scalars(select(Finding).where(Finding.project_id == project.id)))
        assert len(canonical_findings) == 1
        assert canonical_findings[0].scan_id == second_scan.id
    finally:
        db.close()


def test_incomplete_discovery_does_not_deactivate_unseen_asset(monkeypatch) -> None:
    db = _session()
    try:
        project, scan = _project_and_scan(db)
        now = utc_now()
        old_asset = Asset(
            project_id=project.id,
            hostname="legacy.example.org",
            status="active",
            first_seen_at=now - timedelta(days=30),
            last_seen_at=now - timedelta(days=1),
        )
        db.add(old_asset)
        db.commit()
        _patch_scan(monkeypatch, project.main_domain, _network_result(project.main_domain), source_failed=True)

        orchestrator.run_project_scan(scan.id, db)

        db.refresh(scan)
        db.refresh(old_asset)
        assert scan.status == "partial"
        assert "Discovery sources failed" in (scan.partial_reason or "")
        assert old_asset.status == "active"
    finally:
        db.close()


def test_fatal_orchestrator_error_terminalizes_unfinished_manifests(monkeypatch) -> None:
    db = _session()
    try:
        project, scan = _project_and_scan(db)
        _patch_scan(monkeypatch, project.main_domain, _network_result(project.main_domain))
        monkeypatch.setattr(
            orchestrator,
            "_check_scan_health",
            lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("coordinator failure")),
        )

        orchestrator.run_project_scan(scan.id, db)

        db.refresh(scan)
        manifest = db.scalar(select(ScanAssetResult).where(ScanAssetResult.scan_id == scan.id))
        assert manifest is not None
        assert scan.status == "failed"
        assert scan.assets_failed == 1
        assert scan.checks_failed == 4
        assert scan.coverage_percent == 0
        assert "coordinator failure" in (scan.partial_reason or "")
        assert manifest.scan_status == "not_scanned"
        assert manifest.checks["scan"]["status"] == "failed"
        assert manifest.errors[0]["stage"] == "scan"
    finally:
        db.close()


def test_expired_authorization_blocks_queued_execution(monkeypatch) -> None:
    db = _session()
    try:
        project, scan = _project_and_scan(db)
        project.authorization_expires_at = utc_now() - timedelta(seconds=1)
        db.commit()
        monkeypatch.setattr(orchestrator, "_scan_asset_network", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network called")))

        orchestrator.run_project_scan(scan.id, db)

        db.refresh(scan)
        assert scan.status == "failed"
        assert scan.error_message == "Project authorization has expired."
        assert db.scalar(select(func.count()).select_from(ScanAssetResult).where(ScanAssetResult.scan_id == scan.id)) == 0
    finally:
        db.close()


def test_persisted_response_headers_redact_credentials() -> None:
    redacted = orchestrator._redacted_headers(
        {
            "Set-Cookie": "session=super-secret",
            "X-Api-Key": "api-secret",
            "Authentication-Info": "nextnonce=secret",
            "Content-Type": "text/html",
        }
    )

    assert redacted["Set-Cookie"] == "<redacted>"
    assert redacted["X-Api-Key"] == "<redacted>"
    assert redacted["Authentication-Info"] == "<redacted>"
    assert redacted["Content-Type"] == "text/html"
