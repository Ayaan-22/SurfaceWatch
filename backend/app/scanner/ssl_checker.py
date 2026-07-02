import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SslCheckResult:
    issuer: str | None
    subject_common_name: str | None
    subject_alt_names: list[str]
    valid_from: datetime | None
    valid_until: datetime | None
    days_until_expiry: int | None
    expired: bool | None
    self_signed: bool | None
    status: str
    error: str | None = None


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def check_ssl(hostname: str, timeout: float = 3.0) -> SslCheckResult:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
    except Exception as exc:
        return SslCheckResult(None, None, [], None, None, None, None, None, "unknown", str(exc))

    issuer = ", ".join("=".join(part) for group in cert.get("issuer", []) for part in group) or None
    subject = {key: value for group in cert.get("subject", []) for key, value in group}
    common_name = subject.get("commonName")
    alt_names = [value for key, value in cert.get("subjectAltName", []) if key == "DNS"]
    valid_from = _parse_cert_time(cert.get("notBefore"))
    valid_until = _parse_cert_time(cert.get("notAfter"))
    days = (valid_until - datetime.now(timezone.utc)).days if valid_until else None
    expired = days is not None and days < 0
    self_signed = issuer is not None and common_name is not None and common_name in issuer
    status = "healthy"
    if expired:
        status = "expired"
    elif days is not None and days <= 30:
        status = "expiring_soon"
    elif self_signed:
        status = "misconfigured"

    return SslCheckResult(issuer, common_name, alt_names, valid_from, valid_until, days, expired, self_signed, status)
