import logging
import hashlib
import json
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import (
    Asset,
    Change,
    Finding,
    Notification,
    Port,
    Project,
    Scan,
    ScanAssetResult,
    ScanLog,
    SecurityHeader,
    SslResult,
    Technology,
)
from app.models.mixins import utc_now
from app.scanner.headers import analyze_headers
from app.scanner.http_probe import http_targets, probe_http
from app.scanner.dns import resolution_is_public, resolve_host, unsafe_ip_addresses
from app.scanner.ports import check_tcp_ports
from app.scanner.risk_engine import calculate_risk_score
from app.scanner.ssl_checker import SslCheckResult, check_ssl
from app.scanner.subdomains import DiscoveryResult, SubdomainCandidate, discover_subdomains
from app.scanner.tech_fingerprint import detect_technologies
from app.scanner.web_exposure import AGGRESSIVE_EXPOSURE_PATHS, analyze_web_exposures, probe_web_exposure_paths
from app.services.risk import sync_project_risk

logger = logging.getLogger(__name__)

class _ScanCancelled(Exception):
    """Raised when a scan is cancelled or times out globally."""


class _ScanOwnershipLost(Exception):
    """Raised when another worker or recovery process terminates this run."""


class _UnsafeTargetResolution(Exception):
    """Raised when a target resolves to internal or otherwise unsafe IP space."""


def _check_scan_health(
    db: Session,
    scan: Scan,
    start_time: float,
    max_duration: int,
    expected_worker_token: str | None = None,
) -> None:
    """Re-read scan status from DB and enforce global timeout."""
    db.refresh(scan)
    if scan.status == "cancelled":
        raise _ScanCancelled("Scan was cancelled by the user.")
    if expected_worker_token is not None and scan.worker_token != expected_worker_token:
        raise _ScanOwnershipLost("Scan worker lease token changed.")
    if scan.status != "running":
        raise _ScanOwnershipLost(f"Scan execution stopped because status changed to {scan.status}.")
    elapsed = time.monotonic() - start_time
    if elapsed > max_duration:
        raise _ScanCancelled(f"Scan exceeded maximum duration of {max_duration}s.")
    now = utc_now()
    heartbeat_at = scan.heartbeat_at
    if heartbeat_at is not None and heartbeat_at.tzinfo is None:
        heartbeat_at = heartbeat_at.replace(tzinfo=timezone.utc)
    if heartbeat_at is None or (now - heartbeat_at).total_seconds() >= 5:
        scan.heartbeat_at = now
        db.commit()


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
    111: ("RPC service exposed publicly", "high", "Restrict rpcbind to private administration networks."),
    135: ("Windows RPC exposed publicly", "high", "Block public RPC access at the network perimeter."),
    139: ("NetBIOS exposed publicly", "high", "Block public NetBIOS access and use private file-sharing networks."),
    389: ("LDAP exposed publicly", "high", "Restrict directory services and require protected LDAPS connections."),
    1883: ("MQTT exposed publicly", "high", "Require authenticated TLS MQTT and restrict broker access."),
    2181: ("ZooKeeper exposed publicly", "critical", "Block public ZooKeeper access and enforce authenticated private access."),
    2379: ("etcd client API exposed publicly", "critical", "Restrict etcd to the cluster network and require mutual TLS."),
    2380: ("etcd peer API exposed publicly", "critical", "Restrict etcd peer traffic to authenticated cluster members."),
    3128: ("HTTP proxy exposed publicly", "high", "Restrict proxy access and require authentication."),
    3389: ("Remote Desktop exposed publicly", "critical", "Place RDP behind VPN or a hardened access gateway."),
    5672: ("AMQP broker exposed publicly", "high", "Restrict broker access and require authenticated TLS."),
    6443: ("Kubernetes API exposed publicly", "critical", "Restrict the Kubernetes API to trusted administration networks."),
    7001: ("WebLogic administration service exposed", "critical", "Restrict WebLogic administration endpoints and patch supported releases."),
    7002: ("WebLogic TLS service exposed", "high", "Restrict WebLogic administration endpoints to trusted networks."),
    8081: ("Alternate development web port exposed", "medium", "Confirm the service is intended and enforce production access controls."),
    8500: ("Consul API exposed publicly", "critical", "Restrict Consul HTTP access and enable ACLs with TLS."),
    8888: ("Alternate web administration port exposed", "high", "Restrict administrative web interfaces to trusted networks."),
    9090: ("Monitoring or administration port exposed", "high", "Restrict monitoring and administration interfaces."),
    9443: ("Alternate TLS administration port exposed", "high", "Restrict administrative interfaces to trusted networks."),
    10000: ("Web administration service exposed", "high", "Restrict web administration access and require strong authentication."),
    10250: ("Kubelet API exposed publicly", "critical", "Block public kubelet access and require authenticated cluster networking."),
    10255: ("Read-only kubelet API exposed", "critical", "Disable the unauthenticated read-only kubelet port."),
    15672: ("RabbitMQ management exposed publicly", "high", "Restrict the management UI and enforce strong authentication."),
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
            asset_timeout_seconds=settings.aggressive_asset_timeout_seconds,
            exposure_paths=AGGRESSIVE_EXPOSURE_PATHS,
        )
    return ScanProfile(
        name="safe",
        ports=settings.default_ports,
        max_assets=settings.max_discovered_assets,
        asset_timeout_seconds=settings.asset_timeout_seconds,
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


def _finding_identity_evidence(evidence: dict | list | str | None) -> dict | list | str | None:
    """Keep stable discriminators while excluding volatile observation values."""
    if not isinstance(evidence, dict):
        return evidence
    stable_keys = ("port", "protocol", "header", "rule_id", "path", "url")
    identity = {key: evidence[key] for key in stable_keys if key in evidence}
    if "url" in identity and isinstance(identity["url"], str):
        parsed = urlsplit(identity["url"])
        identity["url"] = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path.rstrip('/') or '/'}"
    return identity


def _finding_fingerprint(project: Project, asset: Asset, title: str, category: str, evidence: dict | list | str | None) -> str:
    key = "|".join(
        [
            project.id,
            asset.hostname.lower(),
            category.lower(),
            title.lower(),
            _stable_json(_finding_identity_evidence(evidence)),
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
) -> Finding:
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
        finding = Finding(
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
        db.add(finding)
        db.flush()
        return finding
    finding.scan_id = scan.id
    finding.asset_id = asset.id
    finding.title = title
    finding.description = description
    finding.category = category
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
    return finding


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
        db.flush()
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
        db.flush()
    technology.scan_id = scan.id
    technology.confidence = signal.confidence
    technology.last_seen_at = now



class _UnresolvedTarget(Exception):
    """Raised when a discovery candidate has no current DNS address."""


@dataclass(frozen=True)
class AssetNetworkResult:
    hostname: str
    resolved_ips: list[str]
    http_results: list
    ssl_result: object | None
    port_results: list
    exposure_results: list
    checks: dict[str, dict]
    errors: list[dict]
    tls_results: list[tuple[int, object]] | None = None


TLS_SERVICE_PORTS = {443, 2376, 4443, 6443, 7002, 8443, 9443, 10000, 10250}


def _check_tls_endpoints(hostname: str, connect_ip: str, ports: list[int], timeout: float) -> list[tuple[int, object]]:
    ordered_ports = list(dict.fromkeys(ports))
    results: dict[int, object] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(6, len(ordered_ports))), thread_name_prefix="tls-port") as pool:
        futures = {
            pool.submit(check_ssl, hostname, timeout, connect_ip, port): port
            for port in ordered_ports
        }
        for future, port in futures.items():
            try:
                results[port] = future.result()
            except Exception as exc:
                results[port] = SslCheckResult(
                    None,
                    None,
                    [],
                    None,
                    None,
                    None,
                    None,
                    None,
                    "unknown",
                    str(exc),
                )
    return [(port, results[port]) for port in ordered_ports]


def _check_summary(status: str, planned: int, completed: int, error: str | None = None) -> dict:
    result = {"status": status, "planned": planned, "completed": completed}
    if error:
        result["error"] = error[:500]
    return result


def _scan_asset_network(hostname: str, settings, profile: ScanProfile) -> AssetNetworkResult:
    """Run bounded stages independently so one module cannot erase other results."""
    checks: dict[str, dict] = {}
    errors: list[dict] = []

    resolved_ips = resolve_host(hostname)
    checks["dns"] = _check_summary("completed", 1, 1)
    if not resolved_ips:
        raise _UnresolvedTarget(f"{hostname} has no current A or AAAA resolution.")
    if not settings.allow_internal_targets and not resolution_is_public(resolved_ips):
        unsafe = unsafe_ip_addresses(resolved_ips)
        reason = ", ".join(unsafe) if unsafe else "non-public DNS resolution"
        raise _UnsafeTargetResolution(f"{hostname} resolved outside allowed public scope: {reason}.")

    try:
        port_results = check_tcp_ports(
            resolved_ips[0],
            profile.ports,
            timeout=min(settings.scan_timeout_seconds, 1.5),
            concurrency=settings.port_scan_concurrency,
        )
        errored_ports = [result.port for result in port_results if result.status == "error"]
        if errored_ports:
            checks["ports"] = _check_summary(
                "failed",
                len(profile.ports),
                len(port_results) - len(errored_ports),
                f"Unexpected scanner errors on ports: {', '.join(str(port) for port in errored_ports)}",
            )
            errors.append({"stage": "ports", "error": checks["ports"]["error"]})
        else:
            checks["ports"] = _check_summary("completed", len(profile.ports), len(port_results))
    except Exception as exc:
        port_results = []
        checks["ports"] = _check_summary("failed", len(profile.ports), 0, str(exc))
        errors.append({"stage": "ports", "error": str(exc)})

    open_ports = [result.port for result in port_results if result.status == "open"]
    tls_ports = [443, *(port for port in open_ports if port in TLS_SERVICE_PORTS and port != 443)]
    http_results: list = []
    ssl_result = None
    expected_http = len(http_targets(hostname, open_ports))
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="asset-core") as pool:
        http_future = pool.submit(
            probe_http,
            hostname,
            settings.scan_timeout_seconds,
            open_ports,
            settings.scan_concurrency,
            settings.max_http_body_bytes,
            connect_ip=resolved_ips[0],
        )
        tls_future = pool.submit(
            _check_tls_endpoints,
            hostname,
            resolved_ips[0],
            tls_ports,
            settings.scan_timeout_seconds,
        )
        try:
            http_results = http_future.result()
            checks["http"] = _check_summary("completed", expected_http, len(http_results))
        except Exception as exc:
            checks["http"] = _check_summary("failed", expected_http, 0, str(exc))
            errors.append({"stage": "http", "error": str(exc)})
        try:
            tls_results = tls_future.result()
            ssl_result = next((result for port, result in tls_results if port == 443), None)
            checks["tls"] = _check_summary("completed", len(tls_ports), len(tls_results))
        except Exception as exc:
            tls_results = []
            checks["tls"] = _check_summary("failed", len(tls_ports), 0, str(exc))
            errors.append({"stage": "tls", "error": str(exc)})

    exposure_results: list = []
    if profile.exposure_paths:
        reachable_bases: list[str] = []
        for result in http_results:
            if result.status_code is None:
                continue
            requested = result.requested_url or result.url
            parsed = urlsplit(requested)
            if parsed.scheme and parsed.netloc:
                reachable_bases.append(f"{parsed.scheme}://{parsed.netloc}")
        reachable_bases = list(dict.fromkeys(reachable_bases))
        if reachable_bases:
            selected_base_count = min(len(reachable_bases), settings.max_exposure_endpoints)
            expected_exposures = selected_base_count * len(profile.exposure_paths)
            endpoints_truncated = len(reachable_bases) > settings.max_exposure_endpoints
            try:
                exposure_results = probe_web_exposure_paths(
                    hostname,
                    profile.exposure_paths,
                    settings.scan_timeout_seconds,
                    base_urls=reachable_bases,
                    concurrency=max(4, settings.scan_concurrency * 2),
                    max_body_bytes=settings.max_http_body_bytes,
                    max_base_urls=settings.max_exposure_endpoints,
                    connect_ip=resolved_ips[0],
                )
                truncation_error = (
                    f"Exposure paths were limited to {settings.max_exposure_endpoints} of {len(reachable_bases)} reachable web endpoints."
                    if endpoints_truncated
                    else None
                )
                checks["web_exposure"] = _check_summary(
                    "failed" if endpoints_truncated else "completed",
                    expected_exposures,
                    len(exposure_results),
                    truncation_error,
                )
                checks["web_exposure"]["reachable_endpoints"] = len(reachable_bases)
                checks["web_exposure"]["scanned_endpoints"] = selected_base_count
                if truncation_error:
                    errors.append({"stage": "web_exposure", "error": truncation_error})
            except Exception as exc:
                checks["web_exposure"] = _check_summary("failed", expected_exposures, 0, str(exc))
                errors.append({"stage": "web_exposure", "error": str(exc)})
        else:
            checks["web_exposure"] = _check_summary("skipped", 0, 0, "No reachable HTTP endpoint.")

    for result in http_results:
        if result.error:
            errors.append({"stage": "http_endpoint", "target": result.requested_url or result.url, "error": result.error})
    for port, result in tls_results:
        if getattr(result, "error", None):
            errors.append({"stage": "tls_observation", "target": f"{hostname}:{port}", "error": result.error})

    return AssetNetworkResult(
        hostname=hostname,
        resolved_ips=resolved_ips,
        http_results=http_results,
        ssl_result=ssl_result,
        port_results=port_results,
        exposure_results=exposure_results,
        checks=checks,
        errors=errors,
        tls_results=tls_results,
    )


def _jsonable(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "__dataclass_fields__"):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def _redacted_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        normalized_key = key.lower()
        sensitive_name = normalized_key in {
            "set-cookie",
            "authorization",
            "proxy-authorization",
            "authentication-info",
            "proxy-authentication-info",
        } or any(marker in normalized_key for marker in ("api-key", "apikey", "access-token", "secret"))
        if sensitive_name:
            redacted[key] = "<redacted>"
        else:
            redacted[key] = value[:2000]
    return redacted


def _http_observation(result) -> dict:
    return {
        "requested_url": result.requested_url or result.url,
        "url": result.url,
        "status_code": result.status_code,
        "headers": _redacted_headers(result.headers),
        "redirect_chain": result.redirect_chain,
        "response_time_ms": result.response_time_ms,
        "content_length": result.content_length,
        "tls_verified": result.tls_verified,
        "error": result.error,
    }


def _exposure_observation(result) -> dict:
    normalized_headers = {key.lower(): value for key, value in result.headers.items()}
    return {
        "requested_url": result.requested_url or result.url,
        "url": result.url,
        "path": result.path,
        "status_code": result.status_code,
        "content_type": normalized_headers.get("content-type"),
        "content_length": result.content_length,
        "redirect_chain": result.redirect_chain,
        "response_time_ms": result.response_time_ms,
        "tls_verified": result.tls_verified,
        "error": result.error,
    }


def _finding_observation(finding: Finding) -> dict:
    return {
        "finding_id": finding.id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "category": finding.category,
        "confidence": finding.confidence,
        "cvss_score": finding.cvss_score,
        "status": finding.status,
        "evidence": _jsonable(finding.evidence),
        "business_impact": finding.business_impact,
        "recommendation": finding.recommendation,
        "first_seen_at": _jsonable(finding.first_seen_at),
        "last_seen_at": _jsonable(finding.last_seen_at),
    }


def _canonical_http_result(http_results: list):
    reachable = [result for result in http_results if result.status_code is not None]
    if not reachable:
        return None

    def priority(result) -> tuple:
        parsed = urlsplit(result.requested_url or result.url)
        default_port = parsed.port is None or parsed.port in {80, 443}
        return (parsed.scheme != "https", not default_port, parsed.port or 0)

    return sorted(reachable, key=priority)[0]


def _persist_network_result(
    db: Session,
    project: Project,
    scan: Scan,
    candidate: SubdomainCandidate,
    network: AssetNetworkResult,
) -> tuple[list[str], int, int, int]:
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
    elif asset.status == "inactive":
        db.add(
            Change(
                project_id=project.id,
                scan_id=scan.id,
                asset_id=asset.id,
                change_type="subdomain_reappeared",
                old_value="inactive",
                new_value=candidate.hostname,
                severity="info",
                detected_at=now,
            )
        )

    asset.scan_id = scan.id
    asset.ip_address = network.resolved_ips[0] if network.resolved_ips else None
    has_v4 = any(":" not in address for address in network.resolved_ips)
    has_v6 = any(":" in address for address in network.resolved_ips)
    asset.dns_record_type = "A+AAAA" if has_v4 and has_v6 else "AAAA" if has_v6 else "A"
    asset.source = candidate.source
    asset.status = "active"
    asset.last_seen_at = now

    result_row = db.scalar(
        select(ScanAssetResult).where(
            ScanAssetResult.scan_id == scan.id,
            ScanAssetResult.hostname == candidate.hostname,
        )
    )
    if result_row is None:
        raise RuntimeError(f"Missing scan result manifest for {candidate.hostname}.")
    result_row.asset_id = asset.id
    result_row.ip_addresses = network.resolved_ips

    observed_findings: dict[str, Finding] = {}
    asset_severities: list[str] = []

    def record_finding(
        title: str,
        description: str,
        severity: str,
        category: str,
        evidence: dict,
        business_impact: str,
        recommendation: str,
    ) -> Finding:
        fingerprint = _finding_fingerprint(project, asset, title, category, evidence)
        finding = _create_finding(
            db,
            project,
            scan,
            asset,
            title,
            description,
            severity,
            category,
            evidence,
            business_impact,
            recommendation,
        )
        if fingerprint not in observed_findings:
            observed_findings[fingerprint] = finding
            asset_severities.append(severity)
        return finding

    for exposure in analyze_web_exposures(network.http_results, network.exposure_results):
        record_finding(
            exposure.title,
            exposure.description,
            exposure.severity,
            exposure.category,
            exposure.evidence,
            exposure.business_impact,
            exposure.recommendation,
        )

    canonical_http = _canonical_http_result(network.http_results)
    header_observations: list[dict] = []
    technology_observations: list[dict] = []
    for http_result in network.http_results:
        if http_result.status_code is None:
            continue
        requested_endpoint = http_result.requested_url or http_result.url
        observed_endpoint = http_result.url
        if 300 <= http_result.status_code < 400:
            requested = urlsplit(requested_endpoint)
            secure_redirect = any(urlsplit(url).scheme == "https" for url in http_result.redirect_chain)
            if requested.scheme == "http" and (requested.port is None or requested.port == 80) and not secure_redirect:
                record_finding(
                    "HTTP endpoint does not redirect to HTTPS",
                    "The public HTTP endpoint returned a redirect that did not move clients to HTTPS.",
                    "medium",
                    "Transport Security",
                    {"url": requested_endpoint, "status_code": http_result.status_code},
                    "Users can remain on an unencrypted connection that is vulnerable to interception or modification.",
                    "Redirect all HTTP requests to the equivalent HTTPS URL and enable HSTS after validation.",
                )
            continue
        header_results = analyze_headers(http_result.headers, is_https=urlsplit(observed_endpoint).scheme == "https")
        for header_result in header_results:
            observation = _jsonable(dict(header_result))
            observation["url"] = observed_endpoint
            observation["requested_url"] = requested_endpoint
            if str(observation.get("header_name", "")).lower() == "set-cookie":
                observation["value"] = "<redacted>"
            header_observations.append(observation)
            if http_result is canonical_http:
                _upsert_security_header(db, project, scan, asset, header_result)

            risk_level = str(header_result.get("risk_level", "info"))
            present = bool(header_result.get("present"))
            issue = header_result.get("issue")
            if issue is None:
                issue = risk_level in {"low", "medium", "high", "critical"} and (
                    not present or bool(header_result.get("recommendation"))
                )
            if issue and risk_level in {"low", "medium", "high", "critical"}:
                header_name = str(header_result.get("header_name", "HTTP security header"))
                title = str(
                    header_result.get("title")
                    or (f"Missing {header_name} header" if not present else f"Insecure {header_name} header configuration")
                )
                record_finding(
                    title,
                    str(header_result.get("description") or "A public endpoint has a missing or unsafe HTTP response header."),
                    risk_level,
                    "Security Headers",
                    {
                        "header": header_name,
                        "rule_id": header_result.get("rule_id", header_name),
                        "url": observed_endpoint,
                    },
                    "Missing or weak browser controls can increase client-side attack and information-disclosure risk.",
                    str(header_result.get("recommendation") or "Apply a restrictive, standards-aligned header value."),
                )

        for signal in detect_technologies(http_result.headers, http_result.body_preview):
            _upsert_technology(db, project, scan, asset, signal, now)
            technology_observation = _jsonable(signal)
            technology_observation["url"] = observed_endpoint
            technology_observation["requested_url"] = requested_endpoint
            technology_observations.append(technology_observation)

        requested = urlsplit(requested_endpoint)
        final = urlsplit(http_result.url)
        secure_redirect = final.scheme == "https" or any(urlsplit(url).scheme == "https" for url in http_result.redirect_chain)
        if requested.scheme == "http" and (requested.port is None or requested.port == 80) and not secure_redirect:
            record_finding(
                "HTTP endpoint does not redirect to HTTPS",
                "The public HTTP endpoint returned a response without redirecting clients to HTTPS.",
                "medium",
                "Transport Security",
                {"url": requested_endpoint, "status_code": http_result.status_code},
                "Users can remain on an unencrypted connection that is vulnerable to interception or modification.",
                "Redirect all HTTP requests to the equivalent HTTPS URL and enable HSTS after validation.",
            )

    tls_observations: list[dict] = []
    tls_results = network.tls_results
    if tls_results is None:
        tls_results = [(443, network.ssl_result)] if network.ssl_result is not None else []
    for tls_port, ssl_result in tls_results:
        tls_observations.append({"port": tls_port, **_jsonable(ssl_result)})
        if tls_port == 443:
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
                    tls_versions=[ssl_result.tls_version] if getattr(ssl_result, "tls_version", None) else None,
                    status=ssl_result.status,
                    error=ssl_result.error,
                )
            )
        tls_finding = {
            "expired": (
                "TLS certificate expired",
                "high",
                "The public HTTPS certificate is expired.",
                "Renew and deploy a trusted certificate immediately.",
            ),
            "expiring_soon": (
                "TLS certificate expires soon",
                "medium",
                "The public HTTPS certificate expires within 30 days.",
                "Renew and deploy the certificate before expiry.",
            ),
            "not_yet_valid": (
                "TLS certificate is not yet valid",
                "high",
                "The public endpoint presents a certificate whose validity period has not started.",
                "Deploy a currently valid certificate and verify system clocks and release timing.",
            ),
            "revoked": (
                "Revoked TLS certificate exposed",
                "critical",
                "The public endpoint presents a certificate reported as revoked.",
                "Replace the revoked certificate immediately and investigate the reason for revocation.",
            ),
            "self_signed": (
                "Self-signed TLS certificate exposed",
                "high",
                "The public endpoint presents a self-signed certificate that clients cannot normally trust.",
                "Replace it with a certificate issued by a trusted authority.",
            ),
            "hostname_mismatch": (
                "TLS certificate hostname mismatch",
                "high",
                "The public certificate is not valid for the scanned hostname.",
                "Deploy a certificate whose SAN entries cover this hostname.",
            ),
            "untrusted": (
                "Untrusted TLS certificate chain",
                "high",
                "The endpoint presents a certificate chain that standard clients cannot validate.",
                "Deploy the complete chain from a trusted certificate authority.",
            ),
            "misconfigured": (
                "TLS certificate misconfigured",
                "high",
                "The public endpoint presents a certificate clients may not trust.",
                "Replace it with a valid certificate and complete trusted chain.",
            ),
        }.get(ssl_result.status)
        if tls_finding:
            title, severity, description, recommendation = tls_finding
            evidence = {
                "port": tls_port,
                "status": ssl_result.status,
                "valid_until": ssl_result.valid_until.isoformat() if ssl_result.valid_until else None,
                "days_until_expiry": ssl_result.days_until_expiry,
            }
            record_finding(
                title,
                description,
                severity,
                "SSL/TLS",
                evidence,
                "Certificate trust failures can cause outages, interception warnings, and loss of user confidence.",
                recommendation,
            )
        if getattr(ssl_result, "tls_version", None) in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
            record_finding(
                "Legacy TLS protocol negotiated",
                f"The service on TCP port {tls_port} negotiated {ssl_result.tls_version}.",
                "high",
                "SSL/TLS",
                {"port": tls_port, "tls_version": ssl_result.tls_version},
                "Legacy TLS protocols have known weaknesses and are rejected by modern clients and compliance baselines.",
                "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or TLS 1.3 with modern cipher suites.",
            )
        cipher_name = (getattr(ssl_result, "cipher", None) or "").upper()
        cipher_bits = getattr(ssl_result, "cipher_bits", None)
        if cipher_name and (
            any(marker in cipher_name for marker in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT"))
            or (cipher_bits is not None and cipher_bits < 128)
        ):
            record_finding(
                "Weak TLS cipher negotiated",
                f"The service on TCP port {tls_port} negotiated a weak cipher suite.",
                "high",
                "SSL/TLS",
                {"port": tls_port, "cipher": ssl_result.cipher, "cipher_bits": cipher_bits},
                "Weak encryption can expose traffic to decryption or downgrade risk.",
                "Disable legacy and export cipher suites; prefer AEAD ciphers supported by TLS 1.2 or TLS 1.3.",
            )

    for port_result in network.port_results:
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
            record_finding(
                title,
                "A sensitive, administrative, or development-oriented TCP service is reachable from the public internet.",
                severity,
                "Exposed Services",
                {"port": port_result.port, "protocol": port_result.protocol, "service": port_result.service_guess},
                "Publicly reachable management and data services expand the attack surface and may expose sensitive systems.",
                recommendation,
            )

    db.flush()
    asset.risk_level = _asset_risk_level(asset_severities)
    completed_checks = sum(1 for check in network.checks.values() if check.get("status") in {"completed", "skipped"})
    failed_checks = sum(1 for check in network.checks.values() if check.get("status") == "failed")
    result_row.discovery_status = "active"
    result_row.scan_status = "partial" if failed_checks else "completed"
    result_row.risk_level = asset.risk_level
    result_row.checks = _jsonable(network.checks)
    result_row.http_observations = [_http_observation(result) for result in network.http_results]
    result_row.tls_observations = tls_observations
    result_row.port_observations = [_jsonable(result) for result in network.port_results]
    result_row.header_observations = header_observations
    result_row.technology_observations = technology_observations
    result_row.exposure_observations = [_exposure_observation(result) for result in network.exposure_results]
    result_row.finding_observations = [_finding_observation(finding) for finding in observed_findings.values()]
    result_row.errors = _jsonable(network.errors)
    result_row.finished_at = now
    return asset_severities, len(observed_findings), completed_checks, failed_checks


def _authorization_error(project: Project, scan: Scan) -> str | None:
    if not project.authorization_confirmed:
        return "Project authorization is not confirmed."
    expires_at = project.authorization_expires_at
    if expires_at is None:
        return "Project authorization expiry is missing."
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at.astimezone(timezone.utc) <= utc_now():
        return "Project authorization has expired."
    if scan.scan_profile == "aggressive" and project.max_scan_profile != "aggressive":
        return "Project authorization no longer permits aggressive scanning."
    return None


def _mark_manifest_terminal(
    db: Session,
    scan: Scan,
    hostname: str,
    status: str,
    reason: str,
    expected_checks: int,
    completed: bool,
) -> None:
    row = db.scalar(
        select(ScanAssetResult).where(
            ScanAssetResult.scan_id == scan.id,
            ScanAssetResult.hostname == hostname,
        )
    )
    if row is None:
        return
    now = utc_now()
    row.scan_status = status
    row.finished_at = now
    row.checks = {
        "dns": _check_summary("completed", 1, 1),
        "remaining": _check_summary("skipped" if completed else "not_run", max(0, expected_checks - 1), 0, reason),
    }
    row.errors = [{"stage": "asset", "error": reason}]


def _coverage_percent(completed_checks: int, assets_discovered: int, expected_checks: int) -> int:
    planned = assets_discovered * expected_checks
    if planned <= 0:
        return 0
    return min(100, round((completed_checks / planned) * 100))


def run_project_scan(
    scan_id: str,
    db: Session,
    claimed: bool = False,
    worker_token: str | None = None,
) -> None:
    """Execute a scan exactly once and persist an immutable result manifest."""
    settings = get_settings()
    allowed_statuses = ["claimed"] if claimed else ["queued", "pending"]
    if claimed and not worker_token:
        return
    started_at = utc_now()
    claim_statement = update(Scan).where(Scan.id == scan_id, Scan.status.in_(allowed_statuses))
    if claimed:
        claim_statement = claim_statement.where(Scan.worker_token == worker_token)
    claim_values = {
        "status": "running",
        "started_at": started_at,
        "finished_at": None,
        "error_message": None,
        "heartbeat_at": started_at,
    }
    if not claimed:
        claim_values["worker_token"] = None
        claim_values["attempt_count"] = Scan.attempt_count + 1
    claim = db.execute(
        claim_statement.values(**claim_values).execution_options(synchronize_session=False)
    )
    if claim.rowcount != 1:
        db.rollback()
        return
    db.commit()
    db.expire_all()

    scan = db.get(Scan, scan_id)
    if scan is None:
        return
    project = db.get(Project, scan.project_id)
    if project is None:
        scan.status = "failed"
        scan.finished_at = utc_now()
        scan.worker_token = None
        scan.error_message = "Project not found."
        db.commit()
        return

    authorization_error = _authorization_error(project, scan)
    if authorization_error:
        scan.status = "failed"
        scan.finished_at = utc_now()
        scan.worker_token = None
        scan.error_message = authorization_error
        _log(db, scan, "error", f"Scan blocked: {authorization_error}")
        db.commit()
        return

    profile = _scan_profile(scan, settings)
    _log(db, scan, "info", f"Starting {profile.name} scan for {project.main_domain}.")
    if profile.name == "aggressive":
        _log(
            db,
            scan,
            "warning",
            "Aggressive profile enabled: expanded DNS candidates, service coverage, alternate web ports, and safe exposure probes.",
        )
    db.commit()

    start_time = time.monotonic()
    expected_checks = 5 if profile.exposure_paths else 4
    severities: list[str] = []
    assets_scanned = 0
    assets_failed = 0
    findings_observed = 0
    checks_completed = 0
    checks_failed = 0
    partial_reasons: list[str] = []
    seen_asset_ids: set[str] = set()
    discovery: DiscoveryResult | None = None
    pool: ThreadPoolExecutor | None = None

    try:
        discovery = discover_subdomains(
            project.main_domain,
            settings.discovery_timeout_seconds,
            profile.max_assets,
            aggressive_dns=profile.name == "aggressive",
            resolution_concurrency=max(4, settings.scan_concurrency * 4),
        )
        scan.discovery_metadata = discovery.metadata()
        scan.assets_discovered = len(discovery.candidates)
        failed_sources = [name for name, value in discovery.sources.items() if value.status == "failed"]
        if failed_sources:
            partial_reasons.append(f"Discovery sources failed: {', '.join(failed_sources)}.")
        if discovery.truncated:
            partial_reasons.append(
                f"Discovery returned {len(discovery.candidates)} of {discovery.total_candidates} candidates due to the profile cap."
            )

        for candidate in discovery.candidates:
            now = utc_now()
            asset = db.scalar(select(Asset).where(Asset.project_id == project.id, Asset.hostname == candidate.hostname))
            if asset is not None:
                seen_asset_ids.add(asset.id)
            elif candidate.ip_addresses and (
                settings.allow_internal_targets or resolution_is_public(candidate.ip_addresses)
            ):
                asset = Asset(
                    project_id=project.id,
                    scan_id=scan.id,
                    hostname=candidate.hostname,
                    asset_type="domain" if candidate.hostname == project.main_domain else "subdomain",
                    ip_address=candidate.ip_addresses[0],
                    dns_record_type="A+AAAA" if any(":" in address for address in candidate.ip_addresses) and any(":" not in address for address in candidate.ip_addresses) else "AAAA" if any(":" in address for address in candidate.ip_addresses) else "A",
                    source=candidate.source,
                    status="active",
                    risk_level="unknown",
                    first_seen_at=now,
                    last_seen_at=now,
                )
                db.add(asset)
                db.flush()
                seen_asset_ids.add(asset.id)
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
            if asset is not None and candidate.status == "active":
                asset.scan_id = scan.id
                asset.ip_address = candidate.ip_addresses[0] if candidate.ip_addresses else asset.ip_address
                asset.source = candidate.source
                asset.status = "active"
                asset.last_seen_at = now

            db.add(
                ScanAssetResult(
                    project_id=project.id,
                    scan_id=scan.id,
                    asset_id=asset.id if asset is not None else None,
                    hostname=candidate.hostname,
                    ip_addresses=candidate.ip_addresses,
                    source=candidate.source,
                    discovery_status=candidate.status,
                    scan_status="pending",
                    risk_level="unknown",
                    checks={},
                    http_observations=[],
                    tls_observations=[],
                    port_observations=[],
                    header_observations=[],
                    technology_observations=[],
                    exposure_observations=[],
                    finding_observations=[],
                    errors=[],
                )
            )
        db.commit()

        candidates = iter(discovery.candidates)
        pool = ThreadPoolExecutor(max_workers=settings.scan_concurrency, thread_name_prefix="asset-scan")
        pending: dict = {}

        def submit_next() -> bool:
            try:
                candidate = next(candidates)
            except StopIteration:
                return False
            manifest = db.scalar(
                select(ScanAssetResult).where(
                    ScanAssetResult.scan_id == scan.id,
                    ScanAssetResult.hostname == candidate.hostname,
                )
            )
            if manifest is not None:
                manifest.scan_status = "running"
                manifest.started_at = utc_now()
                db.commit()
            future = pool.submit(_scan_asset_network, candidate.hostname, settings, profile)
            pending[future] = (candidate, time.monotonic())
            return True

        for _ in range(settings.scan_concurrency):
            if not submit_next():
                break

        while pending:
            _check_scan_health(db, scan, start_time, settings.max_scan_duration_seconds, worker_token)
            done, _ = wait(tuple(pending), timeout=0.5, return_when=FIRST_COMPLETED)
            if not done:
                continue
            for future in done:
                candidate, submitted_at = pending.pop(future)
                try:
                    network = future.result()
                    asset_elapsed = time.monotonic() - submitted_at
                    if asset_elapsed > profile.asset_timeout_seconds:
                        deadline_error = (
                            f"Asset work exceeded the {profile.asset_timeout_seconds}s profile budget "
                            f"({asset_elapsed:.1f}s) but completed observations were preserved."
                        )
                        network.checks["asset_deadline"] = _check_summary(
                            "failed",
                            1,
                            0,
                            deadline_error,
                        )
                        network.errors.append({"stage": "asset_deadline", "error": deadline_error})
                    with db.begin_nested():
                        asset_severities, finding_count, completed_count, failed_count = _persist_network_result(
                            db,
                            project,
                            scan,
                            candidate,
                            network,
                        )
                    severities.extend(asset_severities)
                    findings_observed += finding_count
                    checks_completed += completed_count
                    checks_failed += failed_count
                    assets_scanned += 1
                    if failed_count:
                        partial_reasons.append(f"{candidate.hostname}: {failed_count} scanner module(s) failed.")
                    manifest = db.scalar(
                        select(ScanAssetResult).where(
                            ScanAssetResult.scan_id == scan.id,
                            ScanAssetResult.hostname == candidate.hostname,
                        )
                    )
                    if manifest is not None and manifest.asset_id:
                        seen_asset_ids.add(manifest.asset_id)
                except _UnresolvedTarget as exc:
                    assets_scanned += 1
                    checks_completed += expected_checks
                    root_failed = candidate.hostname == project.main_domain
                    if root_failed:
                        assets_failed += 1
                        partial_reasons.append(str(exc))
                    _mark_manifest_terminal(
                        db,
                        scan,
                        candidate.hostname,
                        "failed" if root_failed else "unresolved",
                        str(exc),
                        expected_checks,
                        completed=True,
                    )
                except _UnsafeTargetResolution as exc:
                    assets_scanned += 1
                    assets_failed += 1
                    checks_completed += expected_checks
                    partial_reasons.append(str(exc))
                    _mark_manifest_terminal(
                        db,
                        scan,
                        candidate.hostname,
                        "blocked",
                        str(exc),
                        expected_checks,
                        completed=True,
                    )
                except Exception as exc:
                    db.rollback()
                    scan = db.get(Scan, scan_id)
                    project = db.get(Project, scan.project_id) if scan is not None else None
                    if scan is None or project is None:
                        raise
                    assets_scanned += 1
                    assets_failed += 1
                    checks_failed += expected_checks
                    reason = f"{candidate.hostname} persistence or scan error: {exc}"
                    partial_reasons.append(reason)
                    _mark_manifest_terminal(
                        db,
                        scan,
                        candidate.hostname,
                        "failed",
                        reason,
                        expected_checks,
                        completed=False,
                    )
                    _log(db, scan, "error", reason)

                running_score, _, _ = calculate_risk_score(severities)
                scan.assets_scanned = assets_scanned
                scan.assets_failed = assets_failed
                scan.findings_created = findings_observed
                scan.checks_completed = checks_completed
                scan.checks_failed = checks_failed
                scan.coverage_percent = _coverage_percent(checks_completed, scan.assets_discovered, expected_checks)
                scan.risk_score = running_score
                scan.heartbeat_at = utc_now()
                db.commit()
                submit_next()

        if discovery.complete:
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
        else:
            _log(db, scan, "warning", "Asset disappearance reconciliation skipped because discovery coverage was incomplete.")

        score, _, _ = calculate_risk_score(severities)
        scan.status = "partial" if partial_reasons or checks_failed or assets_failed else "completed"
        scan.finished_at = utc_now()
        scan.assets_scanned = assets_scanned
        scan.assets_failed = assets_failed
        scan.findings_created = findings_observed
        scan.checks_completed = checks_completed
        scan.checks_failed = checks_failed
        scan.coverage_percent = _coverage_percent(checks_completed, scan.assets_discovered, expected_checks)
        scan.risk_score = score
        scan.partial_reason = " ".join(dict.fromkeys(partial_reasons))[:4000] or None
        scan.worker_token = None
        scan.heartbeat_at = utc_now()
        project_score, _ = sync_project_risk(db, project)
        project.last_scan_at = scan.finished_at
        completion_label = "completed" if scan.status == "completed" else "completed with incomplete coverage"
        _log(
            db,
            scan,
            "info" if scan.status == "completed" else "warning",
            f"Scan {completion_label}: {assets_scanned}/{scan.assets_discovered} candidates processed, coverage {scan.coverage_percent}%, risk score {score}.",
        )
        db.add(
            Notification(
                user_id=project.owner_id,
                project_id=project.id,
                title="Scan completed" if scan.status == "completed" else "Scan completed with gaps",
                message=f"{project.company_name} scan coverage: {scan.coverage_percent}%. Project risk score: {project_score}.",
                notification_type="scan_completed",
                metadata_json={
                    "scan_id": scan.id,
                    "risk_score": project_score,
                    "scan_risk_score": score,
                    "coverage_percent": scan.coverage_percent,
                    "status": scan.status,
                },
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

    except _ScanOwnershipLost as ownership_exc:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
            pool = None
        db.rollback()
        logger.warning("Scan %s stopped after losing execution ownership: %s", scan_id, ownership_exc)

    except _ScanCancelled as cancel_exc:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
            pool = None
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        project = db.get(Project, scan.project_id)
        if project is None:
            return
        was_user_cancel = scan.status == "cancelled"
        reason = "cancelled by user" if was_user_cancel else str(cancel_exc)
        pending_status = "cancelled" if was_user_cancel else "not_scanned"
        for manifest in db.scalars(
            select(ScanAssetResult).where(
                ScanAssetResult.scan_id == scan.id,
                ScanAssetResult.scan_status.in_(["pending", "running"]),
            )
        ):
            manifest.scan_status = pending_status
            manifest.finished_at = utc_now()
            manifest.errors = [{"stage": "scan", "error": reason}]
        score, _, _ = calculate_risk_score(severities)
        scan.status = "cancelled" if was_user_cancel else "partial"
        scan.finished_at = utc_now()
        scan.assets_scanned = assets_scanned
        scan.assets_failed = assets_failed + max(0, scan.assets_discovered - assets_scanned)
        scan.findings_created = findings_observed
        scan.checks_completed = checks_completed
        scan.checks_failed = checks_failed
        scan.coverage_percent = _coverage_percent(checks_completed, scan.assets_discovered, expected_checks)
        scan.risk_score = score
        scan.partial_reason = reason
        scan.worker_token = None
        scan.heartbeat_at = utc_now()
        project_score, _ = sync_project_risk(db, project)
        project.last_scan_at = scan.finished_at
        _log(db, scan, "warning", f"Scan stopped early ({reason}). Processed {assets_scanned} candidates.")
        _upsert_scan_stop_notification(
            db,
            project,
            scan,
            "Scan cancelled" if was_user_cancel else "Scan timed out with partial results",
            f"{project.company_name} scan {reason}. Coverage: {scan.coverage_percent}%. Risk score: {project_score}.",
            "scan_cancelled" if was_user_cancel else "scan_completed",
            project_score,
        )
        db.commit()

    except Exception as exc:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        project = db.get(Project, scan.project_id)
        fatal_reason = f"Scan failed before all target work completed: {str(exc)[:3500]}"
        unfinished = 0
        for manifest in db.scalars(
            select(ScanAssetResult).where(
                ScanAssetResult.scan_id == scan.id,
                ScanAssetResult.scan_status.in_(["pending", "running"]),
            )
        ):
            unfinished += 1
            manifest.scan_status = "not_scanned"
            manifest.finished_at = utc_now()
            manifest.checks = {"scan": _check_summary("failed", expected_checks, 0, fatal_reason)}
            manifest.errors = [*(manifest.errors or []), {"stage": "scan", "error": fatal_reason}]
        scan.status = "failed"
        scan.finished_at = utc_now()
        scan.assets_scanned = max(scan.assets_scanned, assets_scanned)
        scan.assets_failed = max(scan.assets_failed, assets_failed + unfinished)
        scan.findings_created = max(scan.findings_created, findings_observed)
        scan.checks_completed = max(scan.checks_completed, checks_completed)
        scan.checks_failed = max(scan.checks_failed, checks_failed + (unfinished * expected_checks))
        scan.coverage_percent = _coverage_percent(scan.checks_completed, scan.assets_discovered, expected_checks)
        scan.partial_reason = fatal_reason
        scan.worker_token = None
        scan.heartbeat_at = utc_now()
        scan.error_message = str(exc)[:4000]
        try:
            _log(db, scan, "error", f"Scan failed: {exc}")
            if project is not None:
                sync_project_risk(db, project)
                project.last_scan_at = scan.finished_at
                db.add(
                    Notification(
                        user_id=project.owner_id,
                        project_id=project.id,
                        title="Scan failed",
                        message=f"{project.company_name} scan failed: {str(exc)[:500]}",
                        notification_type="scan_failed",
                        metadata_json={"scan_id": scan.id},
                    )
                )
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Could not persist terminal failure state for scan %s", scan_id)
    finally:
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
