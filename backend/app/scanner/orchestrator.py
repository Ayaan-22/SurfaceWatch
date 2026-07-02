from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Asset, Change, Finding, Notification, Port, Project, Scan, ScanLog, SecurityHeader, SslResult, Technology
from app.models.mixins import utc_now
from app.scanner.headers import analyze_headers
from app.scanner.http_probe import probe_http
from app.scanner.ports import check_tcp_port
from app.scanner.risk_engine import calculate_risk_score
from app.scanner.ssl_checker import check_ssl
from app.scanner.subdomains import passive_seed_discovery
from app.scanner.tech_fingerprint import detect_technologies


RISKY_PORTS = {
    21: ("FTP exposed publicly", "medium", "Restrict FTP or replace it with a secure transfer workflow."),
    22: ("SSH exposed publicly", "low", "Limit SSH to VPN, bastion hosts, or allowlisted management IPs."),
    3000: ("Development port exposed", "high", "Remove public access or restrict it to an internal network."),
    5000: ("Development port exposed", "high", "Remove public access or restrict it to an internal network."),
    5432: ("Database port exposed", "critical", "Block public PostgreSQL access immediately."),
    3306: ("Database port exposed", "critical", "Block public MySQL access immediately."),
    6379: ("Redis exposed publicly", "critical", "Block public Redis access immediately."),
    9200: ("Elasticsearch exposed publicly", "critical", "Block public Elasticsearch access immediately."),
}


def _log(db: Session, scan: Scan, level: str, message: str) -> None:
    db.add(ScanLog(scan_id=scan.id, level=level, message=message))
    db.flush()


def _asset_risk_level(severities: list[str]) -> str:
    score, level, _ = calculate_risk_score(severities)
    return level if score else "low"


def _create_finding(
    db: Session,
    project: Project,
    scan: Scan,
    asset: Asset,
    title: str,
    description: str,
    severity: str,
    category: str,
    evidence: dict,
    business_impact: str,
    recommendation: str,
) -> None:
    now = utc_now()
    finding = db.scalar(
        select(Finding).where(
            Finding.project_id == project.id,
            Finding.asset_id == asset.id,
            Finding.title == title,
            Finding.category == category,
            Finding.status == "open",
        )
    )
    if finding is None:
        db.add(
            Finding(
                project_id=project.id,
                scan_id=scan.id,
                asset_id=asset.id,
                title=title,
                description=description,
                severity=severity,
                category=category,
                evidence=evidence,
                business_impact=business_impact,
                recommendation=recommendation,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        return
    finding.scan_id = scan.id
    finding.severity = severity
    finding.evidence = evidence
    finding.business_impact = business_impact
    finding.recommendation = recommendation
    finding.last_seen_at = now


def _upsert_security_header(
    db: Session,
    project: Project,
    scan: Scan,
    asset: Asset,
    header_result: dict[str, str | bool | None],
) -> bool | None:
    header_name = str(header_result["header_name"])
    header = db.scalar(select(SecurityHeader).where(SecurityHeader.asset_id == asset.id, SecurityHeader.header_name == header_name))
    if header is None:
        header = SecurityHeader(project_id=project.id, asset_id=asset.id, header_name=header_name)
        db.add(header)
        old_present = None
    else:
        old_present = header.present
    header.scan_id = scan.id
    header.present = bool(header_result["present"])
    header.value = header_result["value"]
    header.recommendation = header_result["recommendation"]
    header.risk_level = str(header_result["risk_level"])
    return old_present


def _upsert_port(db: Session, project: Project, scan: Scan, asset: Asset, port_result, now) -> str | None:
    port = db.scalar(
        select(Port).where(
            Port.asset_id == asset.id,
            Port.port == port_result.port,
            Port.protocol == port_result.protocol,
        )
    )
    if port is None:
        port = Port(
            project_id=project.id,
            asset_id=asset.id,
            port=port_result.port,
            protocol=port_result.protocol,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(port)
        old_status = None
    else:
        old_status = port.status
    port.scan_id = scan.id
    port.status = port_result.status
    port.service_guess = port_result.service_guess
    port.banner = port_result.banner
    port.last_seen_at = now
    return old_status


def _upsert_technology(db: Session, project: Project, scan: Scan, asset: Asset, signal, now) -> None:
    technology = db.scalar(
        select(Technology).where(
            Technology.asset_id == asset.id,
            Technology.name == signal.name,
            Technology.evidence == signal.evidence,
        )
    )
    if technology is None:
        technology = Technology(
            project_id=project.id,
            asset_id=asset.id,
            name=signal.name,
            category=signal.category,
            evidence=signal.evidence,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(technology)
    technology.scan_id = scan.id
    technology.confidence = signal.confidence
    technology.last_seen_at = now


def run_project_scan(scan_id: str, db: Session) -> None:
    settings = get_settings()
    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    project = db.get(Project, scan.project_id)
    if project is None:
        scan.status = "failed"
        scan.error_message = "Project not found."
        db.commit()
        return

    now = utc_now()
    scan.status = "running"
    scan.started_at = now
    _log(db, scan, "info", f"Starting safe scan for {project.main_domain}.")
    db.commit()

    severities: list[str] = []
    assets_scanned = 0
    seen_asset_ids: set[str] = set()
    try:
        for candidate in passive_seed_discovery(
            project.main_domain,
            settings.discovery_timeout_seconds,
            settings.max_discovered_assets,
        ):
            now = utc_now()
            asset = db.scalar(select(Asset).where(Asset.project_id == project.id, Asset.hostname == candidate.hostname))
            if asset is None:
                asset = Asset(
                    project_id=project.id,
                    scan_id=scan.id,
                    hostname=candidate.hostname,
                    asset_type="domain" if candidate.hostname == project.main_domain else "subdomain",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(asset)
                db.flush()
                if candidate.hostname != project.main_domain:
                    db.add(
                        Change(
                            project_id=project.id,
                            scan_id=scan.id,
                            asset_id=asset.id,
                            change_type="new_subdomain_found",
                            old_value=None,
                            new_value=candidate.hostname,
                            severity="info",
                            detected_at=now,
                        )
                    )

            asset.scan_id = scan.id
            asset.ip_address = candidate.ip_addresses[0] if candidate.ip_addresses else None
            asset.dns_record_type = "A"
            asset.source = candidate.source
            asset.status = candidate.status
            asset.last_seen_at = now
            seen_asset_ids.add(asset.id)
            asset_severities: list[str] = []
            assets_scanned += 1
            _log(db, scan, "info", f"Discovered {candidate.hostname} with status {candidate.status}.")

            http_results = probe_http(candidate.hostname, settings.scan_timeout_seconds)
            best_http = next((result for result in http_results if result.status_code), None)
            if best_http:
                for header_result in analyze_headers(best_http.headers):
                    old_present = _upsert_security_header(db, project, scan, asset, header_result)
                    new_present = bool(header_result["present"])
                    if old_present is True and not new_present:
                        db.add(
                            Change(
                                project_id=project.id,
                                scan_id=scan.id,
                                asset_id=asset.id,
                                change_type="security_header_removed",
                                old_value=str(header_result["header_name"]),
                                new_value=None,
                                severity="medium",
                                detected_at=now,
                            )
                        )
                    elif old_present is False and new_present:
                        db.add(
                            Change(
                                project_id=project.id,
                                scan_id=scan.id,
                                asset_id=asset.id,
                                change_type="security_header_added",
                                old_value=None,
                                new_value=str(header_result["header_name"]),
                                severity="info",
                                detected_at=now,
                            )
                        )
                    risk_level = str(header_result["risk_level"])
                    if risk_level in {"low", "medium", "high", "critical"} and not header_result["present"]:
                        asset_severities.append(risk_level)
                        _create_finding(
                            db,
                            project,
                            scan,
                            asset,
                            f"Missing {header_result['header_name']} header",
                            "A recommended HTTP security header is missing from the public endpoint.",
                            risk_level,
                            "Security Headers",
                            {"header": header_result["header_name"], "url": best_http.url},
                            "Missing browser security controls can increase exposure to client-side attacks.",
                            str(header_result["recommendation"]),
                        )
                for signal in detect_technologies(best_http.headers, best_http.body_preview):
                    _upsert_technology(db, project, scan, asset, signal, now)

            ssl_result = check_ssl(candidate.hostname, settings.scan_timeout_seconds)
            db.add(
                SslResult(
                    project_id=project.id,
                    scan_id=scan.id,
                    asset_id=asset.id,
                    issuer=ssl_result.issuer,
                    subject_common_name=ssl_result.subject_common_name,
                    subject_alt_names=ssl_result.subject_alt_names,
                    valid_from=ssl_result.valid_from,
                    valid_until=ssl_result.valid_until,
                    days_until_expiry=ssl_result.days_until_expiry,
                    expired=ssl_result.expired,
                    self_signed=ssl_result.self_signed,
                    status=ssl_result.status,
                    error=ssl_result.error,
                )
            )
            if ssl_result.status == "expired":
                asset_severities.append("high")
                _create_finding(
                    db,
                    project,
                    scan,
                    asset,
                    "TLS certificate expired",
                    "The public HTTPS certificate is expired.",
                    "high",
                    "SSL/TLS",
                    {"valid_until": ssl_result.valid_until.isoformat() if ssl_result.valid_until else None},
                    "Expired certificates can cause outages and browser trust failures.",
                    "Renew and deploy a trusted certificate.",
                )
            elif ssl_result.status == "expiring_soon":
                asset_severities.append("medium")
                _create_finding(
                    db,
                    project,
                    scan,
                    asset,
                    "TLS certificate expires soon",
                    "The public HTTPS certificate expires within 30 days.",
                    "medium",
                    "SSL/TLS",
                    {"days_until_expiry": ssl_result.days_until_expiry},
                    "Certificate expiry can create avoidable downtime.",
                    "Renew and deploy the certificate before expiry.",
                )

            for port_number in settings.default_ports:
                port_result = check_tcp_port(candidate.hostname, port_number, min(settings.scan_timeout_seconds, 1.5))
                old_status = _upsert_port(db, project, scan, asset, port_result, now)
                if old_status == "open" and port_result.status != "open":
                    db.add(
                        Change(
                            project_id=project.id,
                            scan_id=scan.id,
                            asset_id=asset.id,
                            change_type="port_closed",
                            old_value=f"{asset.hostname}:{port_result.port}",
                            new_value=port_result.status,
                            severity="info",
                            detected_at=now,
                        )
                    )
                if port_result.status == "open" and port_result.port in RISKY_PORTS:
                    title, severity, recommendation = RISKY_PORTS[port_result.port]
                    asset_severities.append(severity)
                    if old_status != "open":
                        db.add(
                            Change(
                                project_id=project.id,
                                scan_id=scan.id,
                                asset_id=asset.id,
                                change_type="new_open_port",
                                old_value=old_status,
                                new_value=f"{asset.hostname}:{port_result.port}",
                                severity="medium" if severity in {"low", "medium"} else "high",
                                detected_at=now,
                            )
                        )
                    _create_finding(
                        db,
                        project,
                        scan,
                        asset,
                        title,
                        "A sensitive or development-oriented TCP service is reachable from the public internet.",
                        severity,
                        "Exposed Services",
                        {"port": port_result.port, "service": port_result.service_guess},
                        "Publicly reachable management, database, or development services increase operational risk.",
                        recommendation,
                    )

            asset.risk_level = _asset_risk_level(asset_severities)
            severities.extend(asset_severities)
            db.commit()

        for stale_asset in db.scalars(select(Asset).where(Asset.project_id == project.id, Asset.status == "active")):
            if stale_asset.id not in seen_asset_ids and stale_asset.last_seen_at < scan.started_at:
                stale_asset.status = "inactive"
                db.add(
                    Change(
                        project_id=project.id,
                        scan_id=scan.id,
                        asset_id=stale_asset.id,
                        change_type="subdomain_disappeared",
                        old_value=stale_asset.hostname,
                        new_value="inactive",
                        severity="info",
                        detected_at=utc_now(),
                    )
                )

        score, level, _ = calculate_risk_score(severities)
        scan.status = "completed"
        scan.finished_at = utc_now()
        scan.assets_scanned = assets_scanned
        scan.findings_created = len(severities)
        scan.risk_score = score
        project.risk_score = score
        project.risk_level = level
        project.risk_status = "attention_required" if score > 50 else "monitored"
        project.last_scan_at = scan.finished_at
        _log(db, scan, "info", f"Scan completed with risk score {score}.")
        db.add(
            Notification(
                user_id=project.owner_id,
                project_id=project.id,
                title="Scan completed",
                message=f"{project.company_name} scan completed with risk score {score}.",
                notification_type="scan_completed",
                metadata_json={"scan_id": scan.id, "risk_score": score},
            )
        )
        if any(severity in {"critical", "high"} for severity in severities):
            db.add(
                Notification(
                    user_id=project.owner_id,
                    project_id=project.id,
                    title="High risk finding detected",
                    message="The latest scan found at least one high or critical risk item.",
                    notification_type="high_finding",
                    metadata_json={"scan_id": scan.id},
                )
            )
        db.commit()
    except Exception as exc:
        scan.status = "failed"
        scan.finished_at = utc_now()
        scan.error_message = str(exc)
        _log(db, scan, "error", f"Scan failed: {exc}")
        db.add(
            Notification(
                user_id=project.owner_id,
                project_id=project.id,
                title="Scan failed",
                message=f"{project.company_name} scan failed: {exc}",
                notification_type="scan_failed",
                metadata_json={"scan_id": scan.id},
            )
        )
        db.commit()
