import logging
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Asset, Change, Finding, Notification, Port, Project, Scan, ScanLog, SecurityHeader, SslResult, Technology
from app.models.mixins import utc_now
from app.scanner.headers import analyze_headers
from app.scanner.http_probe import probe_http
from app.scanner.dns import resolution_is_public, resolve_host, unsafe_ip_addresses
from app.scanner.ports import check_tcp_port
from app.scanner.risk_engine import calculate_risk_score
from app.scanner.ssl_checker import check_ssl
from app.scanner.subdomains import iter_passive_seed_discovery
from app.scanner.tech_fingerprint import detect_technologies
from app.scanner.web_exposure import AGGRESSIVE_EXPOSURE_PATHS, analyze_web_exposures, probe_web_exposure_paths
from app.services.risk import sync_project_risk

logger = logging.getLogger(__name__)

# Thread pool for running per-asset work with a hard timeout
_ASSET_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="asset-scan")

ASSET_TIMEOUT_SECONDS = 30  # Max time for a single asset (HTTP + SSL + ports)


class _ScanCancelled(Exception):
    """Raised when a scan is cancelled or times out globally."""


class _UnsafeTargetResolution(Exception):
    """Raised when a target resolves to internal or otherwise unsafe IP space."""


def _check_scan_health(db: Session, scan: Scan, start_time: float, max_duration: int) -> None:
    """Re-read scan status from DB and enforce global timeout."""
    db.refresh(scan)
    if scan.status == "cancelled":
        raise _ScanCancelled("Scan was cancelled by the user.")
    elapsed = time.monotonic() - start_time
    if elapsed > max_duration:
        raise _ScanCancelled(f"Scan exceeded maximum duration of {max_duration}s.")


RISKY_PORTS = {
    21: ("FTP exposed publicly", "medium", "Restrict FTP or replace it with a secure transfer workflow."),
    22: ("SSH exposed publicly", "low", "Limit SSH to VPN, bastion hosts, or allowlisted management IPs."),
    23: ("Telnet exposed publicly", "critical", "Disable Telnet and replace it with SSH through a restricted management path."),
    445: ("SMB exposed publicly", "high", "Block public SMB access and restrict file sharing to private networks."),
    1433: ("Database port exposed", "critical", "Block public Microsoft SQL Server access immediately."),
    1521: ("Database port exposed", "critical", "Block public Oracle database access immediately."),
    2049: ("NFS exposed publicly", "high", "Block public NFS access and restrict file shares to private networks."),
    2375: ("Docker API exposed publicly", "critical", "Disable unauthenticated Docker API exposure and restrict daemon access."),
    2376: ("Docker API exposed publicly", "high", "Restrict Docker API access to trusted administration networks."),
    3000: ("Development port exposed", "high", "Remove public access or restrict it to an internal network."),
    5000: ("Development port exposed", "high", "Remove public access or restrict it to an internal network."),
    5432: ("Database port exposed", "critical", "Block public PostgreSQL access immediately."),
    5601: ("Kibana exposed publicly", "high", "Restrict Kibana to VPN, SSO, or trusted administration networks."),
    5900: ("VNC exposed publicly", "critical", "Block public VNC access and require private network access."),
    5984: ("CouchDB exposed publicly", "critical", "Block public CouchDB access immediately."),
    3306: ("Database port exposed", "critical", "Block public MySQL access immediately."),
    6379: ("Redis exposed publicly", "critical", "Block public Redis access immediately."),
    9000: ("Administrative service exposed", "high", "Restrict administrative interfaces to trusted networks."),
    9200: ("Elasticsearch exposed publicly", "critical", "Block public Elasticsearch access immediately."),
    9300: ("Elasticsearch transport exposed publicly", "critical", "Block public Elasticsearch transport access immediately."),
    11211: ("Memcached exposed publicly", "critical", "Block public Memcached access immediately."),
    27017: ("MongoDB exposed publicly", "critical", "Block public MongoDB access immediately."),
    27018: ("MongoDB exposed publicly", "critical", "Block public MongoDB access immediately."),
}


@dataclass(frozen=True)
class ScanProfile:
    name: str
    ports: list[int]
    max_assets: int
    asset_timeout_seconds: int
    exposure_paths: list[str]


def _scan_profile(scan: Scan, settings) -> ScanProfile:
    profile = scan.scan_profile if scan.scan_profile in {"safe", "aggressive"} else "safe"
    if profile == "aggressive":
        return ScanProfile(
            name="aggressive",
            ports=settings.aggressive_ports,
            max_assets=settings.aggressive_max_discovered_assets,
            asset_timeout_seconds=max(ASSET_TIMEOUT_SECONDS, 60),
            exposure_paths=AGGRESSIVE_EXPOSURE_PATHS,
        )
    return ScanProfile(
        name="safe",
        ports=settings.default_ports,
        max_assets=settings.max_discovered_assets,
        asset_timeout_seconds=ASSET_TIMEOUT_SECONDS,
        exposure_paths=[],
    )


def _log(db: Session, scan: Scan, level: str, message: str) -> None:
    db.add(ScanLog(scan_id=scan.id, level=level, message=message))
    db.flush()


def _upsert_scan_stop_notification(
    db: Session,
    project: Project,
    scan: Scan,
    title: str,
    message: str,
    notification_type: str,
    risk_score: int,
) -> None:
    notification = None
    for existing in db.scalars(
        select(Notification).where(
            Notification.user_id == project.owner_id,
            Notification.project_id == project.id,
            Notification.notification_type.in_(["scan_completed", "scan_cancelled"]),
        )
    ):
        metadata = existing.metadata_json or {}
        if isinstance(metadata, dict) and metadata.get("scan_id") == scan.id:
            notification = existing
            break

    if notification is None:
        db.add(
            Notification(
                user_id=project.owner_id,
                project_id=project.id,
                title=title,
                message=message,
                notification_type=notification_type,
                metadata_json={"scan_id": scan.id, "risk_score": risk_score, "scan_risk_score": scan.risk_score},
            )
        )
        return

    notification.title = title
    notification.message = message
    notification.notification_type = notification_type
    notification.metadata_json = {"scan_id": scan.id, "risk_score": risk_score, "scan_risk_score": scan.risk_score}
    notification.is_read = False


def _asset_risk_level(severities: list[str]) -> str:
    score, level, _ = calculate_risk_score(severities)
    return level if score else "low"


SLA_DAYS_BY_SEVERITY = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 90,
    "info": 180,
}


CVSS_BY_SEVERITY = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 2.5,
    "info": 0.0,
}


def _stable_json(value: dict | list | str | None) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _finding_fingerprint(project: Project, asset: Asset, title: str, category: str, evidence: dict | list | str | None) -> str:
    key = "|".join(
        [
            project.id,
            asset.hostname.lower(),
            category.lower(),
            title.lower(),
            _stable_json(evidence),
        ]
    )
    return _hash_text(key)


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
    fingerprint = _finding_fingerprint(project, asset, title, category, evidence)
    evidence_hash = _hash_text(_stable_json(evidence))
    normalized_severity = severity.lower()
    sla_due_at = now + timedelta(days=SLA_DAYS_BY_SEVERITY.get(normalized_severity, 30))
    finding = db.scalar(
        select(Finding).where(
            Finding.project_id == project.id,
            Finding.fingerprint == fingerprint,
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
                fingerprint=fingerprint,
                confidence="high",
                cvss_score=CVSS_BY_SEVERITY.get(normalized_severity),
                evidence_hash=evidence_hash,
                sla_due_at=sla_due_at,
                evidence=evidence,
                business_impact=business_impact,
                recommendation=recommendation,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        return
    finding.scan_id = scan.id
    finding.asset_id = asset.id
    finding.severity = severity
    finding.confidence = "high"
    finding.cvss_score = CVSS_BY_SEVERITY.get(normalized_severity)
    finding.evidence_hash = evidence_hash
    if finding.status == "fixed":
        finding.status = "open"
        finding.sla_due_at = sla_due_at
    elif finding.sla_due_at is None:
        finding.sla_due_at = sla_due_at
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


def _scan_asset_network(hostname: str, settings, profile: ScanProfile) -> tuple:
    """Run all network I/O for a single asset. Executed in a thread so we can enforce a hard timeout."""
    resolved_ips = resolve_host(hostname)
    if not settings.allow_internal_targets and not resolution_is_public(resolved_ips):
        unsafe = unsafe_ip_addresses(resolved_ips)
        reason = ", ".join(unsafe) if unsafe else "no public DNS resolution"
        raise _UnsafeTargetResolution(f"{hostname} resolved outside allowed public scope: {reason}.")
    http_results = probe_http(hostname, settings.scan_timeout_seconds)
    ssl_result = check_ssl(hostname, settings.scan_timeout_seconds)
    port_results = []
    for port_number in profile.ports:
        port_results.append(check_tcp_port(hostname, port_number, min(settings.scan_timeout_seconds, 1.5)))
    exposure_results = []
    if profile.exposure_paths:
        exposure_results = probe_web_exposure_paths(hostname, profile.exposure_paths, settings.scan_timeout_seconds)
    return http_results, ssl_result, port_results, exposure_results


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
    if scan.status == "cancelled":
        return
    profile = _scan_profile(scan, settings)

    now = utc_now()
    scan.status = "running"
    scan.started_at = now
    _log(db, scan, "info", f"Starting {profile.name} scan for {project.main_domain}.")
    if profile.name == "aggressive":
        _log(
            db,
            scan,
            "warning",
            "Aggressive profile enabled: expanded port coverage and deeper HTTP exposure probes will run within the authorized scope.",
        )
    db.commit()

    start_time = time.monotonic()
    max_duration = settings.max_scan_duration_seconds
    severities: list[str] = []
    assets_scanned = 0
    seen_asset_ids: set[str] = set()

    try:
        for candidate in iter_passive_seed_discovery(
            project.main_domain,
            settings.discovery_timeout_seconds,
            profile.max_assets,
        ):
            _check_scan_health(db, scan, start_time, max_duration)

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
            running_score, _, _ = calculate_risk_score(severities)
            scan.assets_scanned = assets_scanned
            scan.findings_created = len(severities)
            scan.risk_score = running_score
            db.commit()

            try:
                future = _ASSET_POOL.submit(_scan_asset_network, candidate.hostname, settings, profile)
                http_results, ssl_result, port_results, exposure_results = future.result(timeout=profile.asset_timeout_seconds)
                _check_scan_health(db, scan, start_time, max_duration)
            except FuturesTimeoutError:
                logger.warning("Asset %s timed out after %ds, skipping deep scan.", candidate.hostname, profile.asset_timeout_seconds)
                _log(db, scan, "warning", f"Asset {candidate.hostname} timed out after {profile.asset_timeout_seconds}s, skipping.")
                future.cancel()
                _check_scan_health(db, scan, start_time, max_duration)
                asset.risk_level = "unknown"
                running_score, _, _ = calculate_risk_score(severities)
                scan.assets_scanned = assets_scanned
                scan.findings_created = len(severities)
                scan.risk_score = running_score
                db.commit()
                continue
            except _UnsafeTargetResolution as exc:
                logger.warning("Asset %s blocked by target safety guard: %s", candidate.hostname, exc)
                _log(db, scan, "warning", str(exc))
                asset.status = "blocked"
                asset.risk_level = "unknown"
                running_score, _, _ = calculate_risk_score(severities)
                scan.assets_scanned = assets_scanned
                scan.findings_created = len(severities)
                scan.risk_score = running_score
                db.commit()
                continue
            except _ScanCancelled:
                raise
            except Exception as exc:
                logger.warning("Asset %s network scan failed: %s", candidate.hostname, exc)
                _log(db, scan, "warning", f"Asset {candidate.hostname} scan error: {exc}")
                asset.risk_level = "unknown"
                running_score, _, _ = calculate_risk_score(severities)
                scan.assets_scanned = assets_scanned
                scan.findings_created = len(severities)
                scan.risk_score = running_score
                db.commit()
                continue

            for exposure in analyze_web_exposures(http_results, exposure_results):
                asset_severities.append(exposure.severity)
                _create_finding(
                    db,
                    project,
                    scan,
                    asset,
                    exposure.title,
                    exposure.description,
                    exposure.severity,
                    exposure.category,
                    exposure.evidence,
                    exposure.business_impact,
                    exposure.recommendation,
                )

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

            for port_result in port_results:
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

            running_score, _, _ = calculate_risk_score(severities)
            scan.assets_scanned = assets_scanned
            scan.findings_created = len(severities)
            scan.risk_score = running_score

            db.commit()

        _check_scan_health(db, scan, start_time, max_duration)

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

        score, _, _ = calculate_risk_score(severities)
        scan.status = "completed"
        scan.finished_at = utc_now()
        scan.assets_scanned = assets_scanned
        scan.findings_created = len(severities)
        scan.risk_score = score
        project_score, _ = sync_project_risk(db, project)
        project.last_scan_at = scan.finished_at
        _log(db, scan, "info", f"Scan completed with risk score {score}.")
        db.add(
            Notification(
                user_id=project.owner_id,
                project_id=project.id,
                title="Scan completed",
                message=f"{project.company_name} scan completed with risk score {project_score}.",
                notification_type="scan_completed",
                metadata_json={"scan_id": scan.id, "risk_score": project_score, "scan_risk_score": score},
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

    except _ScanCancelled as cancel_exc:
        score, _, _ = calculate_risk_score(severities)
        db.refresh(scan)
        was_user_cancel = scan.status == "cancelled"
        scan.status = "cancelled" if was_user_cancel else "completed"
        scan.finished_at = utc_now()
        scan.assets_scanned = assets_scanned
        scan.findings_created = len(severities)
        scan.risk_score = score
        project_score, _ = sync_project_risk(db, project)
        project.last_scan_at = scan.finished_at
        reason = "cancelled by user" if was_user_cancel else str(cancel_exc)
        _log(db, scan, "info", f"Scan stopped early ({reason}). Processed {assets_scanned} assets.")
        _upsert_scan_stop_notification(
            db,
            project,
            scan,
            "Scan cancelled" if was_user_cancel else "Scan completed (partial)",
            f"{project.company_name} scan {reason}. Risk score: {project_score}.",
            "scan_cancelled" if was_user_cancel else "scan_completed",
            project_score,
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
