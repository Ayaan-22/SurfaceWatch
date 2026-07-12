from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401
from app.database import Base
from app.models import Project, Scan, ScanAssetResult, User
from app.models.mixins import utc_now
from app.scanner import worker
from app.scanner.orchestrator import run_project_scan


def _factory():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def _project(db, suffix: str = "one") -> Project:
    user = User(email=f"worker-{suffix}@example.org", full_name="Worker", hashed_password="hash")
    project = Project(owner=user, company_name="Worker Org", main_domain=f"worker-{suffix}.example.org")
    db.add_all([user, project])
    db.flush()
    return project


def test_worker_claim_is_exactly_once(monkeypatch) -> None:
    factory = _factory()
    db = factory()
    project = _project(db)
    scan = Scan(project=project, status="queued")
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.close()
    monkeypatch.setattr(worker, "SessionLocal", factory)

    claim = worker.claim_next_scan()
    assert claim is not None
    assert claim[0] == scan_id
    assert len(claim[1]) == 32
    assert worker.claim_next_scan() is None

    check = factory()
    try:
        claimed_scan = check.get(Scan, scan_id)
        assert claimed_scan.status == "claimed"
        assert claimed_scan.worker_token == claim[1]
        assert claimed_scan.attempt_count == 1
    finally:
        check.close()


def test_worker_recovers_abandoned_claim_and_expires_stale_run() -> None:
    factory = _factory()
    db = factory()
    try:
        project = _project(db, "claimed")
        other_project = _project(db, "running")
        old = utc_now() - timedelta(days=1)
        claimed = Scan(project=project, status="claimed", updated_at=old)
        running = Scan(
            project=other_project,
            status="running",
            scan_profile="safe",
            assets_discovered=1,
            checks_completed=1,
            coverage_percent=25,
            updated_at=old,
        )
        db.add_all([claimed, running])
        db.flush()
        manifest = ScanAssetResult(
            project_id=other_project.id,
            scan_id=running.id,
            hostname=other_project.main_domain,
            ip_addresses=["93.184.216.34"],
            source="passive_seed_dns",
            discovery_status="active",
            scan_status="running",
        )
        db.add(manifest)
        db.commit()

        worker._recover_stale_scans(db)

        db.refresh(claimed)
        db.refresh(running)
        assert claimed.status == "queued"
        assert "Recovered" in (claimed.error_message or "")
        assert running.status == "failed"
        assert running.finished_at is not None
        assert "heartbeat expired" in (running.error_message or "")
        assert running.assets_failed == 1
        assert running.checks_failed == 4
        assert running.coverage_percent == 25
        assert manifest.scan_status == "not_scanned"
        assert manifest.checks["scan"]["status"] == "failed"
        assert manifest.errors[0]["stage"] == "worker"
    finally:
        db.close()


def test_expired_worker_token_cannot_steal_replacement_claim(monkeypatch) -> None:
    factory = _factory()
    db = factory()
    project = _project(db, "lease")
    scan = Scan(project=project, status="queued")
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.close()
    monkeypatch.setattr(worker, "SessionLocal", factory)

    first_claim = worker.claim_next_scan()
    assert first_claim is not None
    recovery = factory()
    try:
        claimed_scan = recovery.get(Scan, scan_id)
        claimed_scan.status = "queued"
        claimed_scan.worker_token = None
        recovery.commit()
    finally:
        recovery.close()
    second_claim = worker.claim_next_scan()
    assert second_claim is not None
    assert first_claim[1] != second_claim[1]

    stale_worker_db = factory()
    try:
        run_project_scan(scan_id, stale_worker_db, claimed=True, worker_token=first_claim[1])
    finally:
        stale_worker_db.close()

    check = factory()
    try:
        current = check.get(Scan, scan_id)
        assert current.status == "claimed"
        assert current.worker_token == second_claim[1]
    finally:
        check.close()
