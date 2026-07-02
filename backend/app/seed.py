from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Change, Finding, Port, Project, Scan, SecurityHeader, SslResult, Technology, User
from app.models.mixins import utc_now
from app.services.security import hash_password


def seed_demo_data(db: Session) -> None:
    existing = db.scalar(select(User).where(User.email == "demo@surfacewatch.dev"))
    if existing:
        project = db.scalar(select(Project).where(Project.owner_id == existing.id))
        if project:
            project.main_domain = "northstar-demo.test"
            for asset in project.assets:
                asset.hostname = asset.hostname.replace("example.com", "northstar-demo.test")
            db.commit()
        return

    now = utc_now()
    user = User(
        email="demo@surfacewatch.dev",
        full_name="SurfaceWatch Demo",
        hashed_password=hash_password("SurfaceWatchDemo123!"),
        role="admin",
    )
    project = Project(
        owner=user,
        company_name="Northstar Demo Co.",
        main_domain="northstar-demo.test",
        description="Seed project with safe, fictional exposure data for dashboard demos.",
        authorization_confirmed=True,
        scan_frequency="weekly",
        risk_score=62,
        risk_level="high",
        risk_status="attention_required",
        last_scan_at=now,
        next_scan_at=now + timedelta(days=7),
    )
    scan = Scan(project=project, status="completed", started_at=now - timedelta(minutes=4), finished_at=now, assets_scanned=4, findings_created=6, risk_score=62)
    assets = [
        Asset(project=project, scan=scan, hostname="northstar-demo.test", ip_address="203.0.113.10", status="active", source="demo_seed", first_seen_at=now - timedelta(days=20), last_seen_at=now),
        Asset(project=project, scan=scan, hostname="api.northstar-demo.test", ip_address="203.0.113.11", status="active", source="demo_seed", first_seen_at=now - timedelta(days=14), last_seen_at=now),
        Asset(project=project, scan=scan, hostname="dev.northstar-demo.test", ip_address="203.0.113.12", status="active", source="demo_seed", first_seen_at=now - timedelta(days=1), last_seen_at=now),
    ]
    db.add_all([user, project, scan, *assets])
    db.flush()

    db.add_all(
        [
            Port(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, port=80, protocol="tcp", status="open", service_guess="http", first_seen_at=now - timedelta(days=20), last_seen_at=now),
            Port(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, port=443, protocol="tcp", status="open", service_guess="https", first_seen_at=now - timedelta(days=20), last_seen_at=now),
            Port(project_id=project.id, scan_id=scan.id, asset_id=assets[2].id, port=3000, protocol="tcp", status="open", service_guess="node-dev", first_seen_at=now - timedelta(days=1), last_seen_at=now),
            SslResult(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, issuer="CN=Demo CA", subject_common_name="northstar-demo.test", subject_alt_names=["northstar-demo.test", "www.northstar-demo.test"], valid_from=now - timedelta(days=60), valid_until=now + timedelta(days=18), days_until_expiry=18, expired=False, self_signed=False, status="expiring_soon"),
            SecurityHeader(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, header_name="strict-transport-security", present=False, risk_level="medium", recommendation="Add HSTS after confirming HTTPS coverage."),
            SecurityHeader(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, header_name="content-security-policy", present=True, value="default-src 'self'", risk_level="info"),
            Technology(project_id=project.id, scan_id=scan.id, asset_id=assets[0].id, name="Next.js", category="Frontend Framework", confidence=85, evidence="Matched _next/ static asset path", first_seen_at=now - timedelta(days=20), last_seen_at=now),
            Technology(project_id=project.id, scan_id=scan.id, asset_id=assets[2].id, name="Express", category="Backend Framework", confidence=85, evidence="X-Powered-By: Express", first_seen_at=now - timedelta(days=1), last_seen_at=now),
            Finding(project=project, scan=scan, asset=assets[0], title="Certificate expires soon", description="The public TLS certificate expires within 30 days.", severity="medium", category="SSL/TLS", evidence={"days_until_expiry": 18}, business_impact="Expired certificates can cause outages and reduce customer trust.", recommendation="Renew and deploy the certificate before expiry.", first_seen_at=now, last_seen_at=now),
            Finding(project=project, scan=scan, asset=assets[0], title="Missing HSTS header", description="The HTTPS endpoint does not advertise Strict-Transport-Security.", severity="medium", category="Security Headers", evidence={"header": "Strict-Transport-Security"}, business_impact="Users may be vulnerable to protocol downgrade attempts.", recommendation="Add HSTS once HTTPS is stable across subdomains.", first_seen_at=now, last_seen_at=now),
            Finding(project=project, scan=scan, asset=assets[2], title="Development port exposed", description="A development service port is reachable from the public internet.", severity="high", category="Exposed Services", evidence={"port": 3000}, business_impact="Development services may expose debugging information or weak controls.", recommendation="Restrict the service to VPN or remove public exposure.", first_seen_at=now, last_seen_at=now),
            Change(project=project, scan_id=scan.id, asset_id=assets[2].id, change_type="new_open_port", old_value=None, new_value="dev.example.com:3000", severity="medium", detected_at=now),
        ]
    )
    db.commit()
