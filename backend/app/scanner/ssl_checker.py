import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID


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
    # Appended fields keep existing positional construction and callers compatible.
    tls_version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    certificate_verified: bool | None = None
    verification_error: str | None = None


@dataclass(frozen=True)
class _CertificateMetadata:
    issuer: str | None = None
    subject_common_name: str | None = None
    subject_alt_names: tuple[str, ...] = ()
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    self_signed: bool | None = None


@dataclass(frozen=True)
class _TlsObservation:
    certificate: dict
    certificate_der: bytes | None
    tls_version: str | None
    cipher: str | None
    cipher_bits: int | None


_EXPIRED_VERIFY_CODES = {10}
_NOT_YET_VALID_VERIFY_CODES = {9}
_REVOKED_VERIFY_CODES = {23}
_HOSTNAME_VERIFY_CODES = {62}
_SELF_SIGNED_VERIFY_CODES = {18, 19}


def _parse_cert_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _days_until(valid_until: datetime | None, now: datetime | None = None) -> int | None:
    valid_until = _as_utc(valid_until)
    if valid_until is None:
        return None
    current = _as_utc(now) if now is not None else datetime.now(timezone.utc)
    assert current is not None
    return int((valid_until - current).total_seconds() // 86_400)


def _classify_certificate_health(
    days_until_expiry: int | None,
    self_signed: bool | None,
) -> str:
    if days_until_expiry is not None and days_until_expiry < 0:
        return "expired"
    if self_signed:
        return "self_signed"
    if days_until_expiry is not None and days_until_expiry <= 30:
        return "expiring_soon"
    return "healthy"


def _classify_verification_failure(
    verify_code: int | None,
    verify_message: str | None,
    *,
    expired: bool | None = None,
    self_signed: bool | None = None,
) -> str:
    """Map OpenSSL verification details to stable scanner statuses without I/O."""
    message = (verify_message or "").lower()
    if expired or verify_code in _EXPIRED_VERIFY_CODES or "expired" in message:
        return "expired"
    if verify_code in _NOT_YET_VALID_VERIFY_CODES or "not yet valid" in message:
        return "not_yet_valid"
    if verify_code in _REVOKED_VERIFY_CODES or "revoked" in message:
        return "revoked"
    if verify_code in _HOSTNAME_VERIFY_CODES or any(
        marker in message for marker in ("hostname mismatch", "doesn't match", "does not match", "not valid for")
    ):
        return "hostname_mismatch"
    if self_signed or verify_code in _SELF_SIGNED_VERIFY_CODES or "self-signed" in message or "self signed" in message:
        return "self_signed"
    return "untrusted"


def _metadata_from_stdlib(certificate: dict) -> _CertificateMetadata:
    issuer_parts = certificate.get("issuer", [])
    subject_parts = certificate.get("subject", [])
    issuer = ", ".join("=".join(part) for group in issuer_parts for part in group) or None
    subject = {key: value for group in subject_parts for key, value in group}
    alt_names = tuple(
        str(value)
        for key, value in certificate.get("subjectAltName", [])
        if key in {"DNS", "IP Address"}
    )
    return _CertificateMetadata(
        issuer=issuer,
        subject_common_name=subject.get("commonName"),
        subject_alt_names=alt_names,
        valid_from=_parse_cert_time(certificate.get("notBefore")),
        valid_until=_parse_cert_time(certificate.get("notAfter")),
        self_signed=bool(issuer_parts and subject_parts and issuer_parts == subject_parts),
    )


def _metadata_from_der(certificate_der: bytes) -> _CertificateMetadata:
    certificate = x509.load_der_x509_certificate(certificate_der)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    alt_names: list[str] = []
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        alt_names.extend(san.get_values_for_type(x509.DNSName))
        alt_names.extend(str(value) for value in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass

    valid_from = getattr(certificate, "not_valid_before_utc", None)
    valid_until = getattr(certificate, "not_valid_after_utc", None)
    if valid_from is None:
        valid_from = _as_utc(certificate.not_valid_before)
    if valid_until is None:
        valid_until = _as_utc(certificate.not_valid_after)

    return _CertificateMetadata(
        issuer=certificate.issuer.rfc4514_string() or None,
        subject_common_name=common_name,
        subject_alt_names=tuple(alt_names),
        valid_from=_as_utc(valid_from),
        valid_until=_as_utc(valid_until),
        self_signed=certificate.issuer == certificate.subject,
    )


def _empty_result(status: str, error: str) -> SslCheckResult:
    return SslCheckResult(
        issuer=None,
        subject_common_name=None,
        subject_alt_names=[],
        valid_from=None,
        valid_until=None,
        days_until_expiry=None,
        expired=None,
        self_signed=None,
        status=status,
        error=error,
    )


def _build_result(
    metadata: _CertificateMetadata,
    observation: _TlsObservation,
    *,
    certificate_verified: bool,
    verification_error: str | None = None,
    verification_status: str | None = None,
) -> SslCheckResult:
    days = _days_until(metadata.valid_until)
    expired = days < 0 if days is not None else None
    status = verification_status or _classify_certificate_health(days, metadata.self_signed)
    return SslCheckResult(
        issuer=metadata.issuer,
        subject_common_name=metadata.subject_common_name,
        subject_alt_names=list(metadata.subject_alt_names),
        valid_from=metadata.valid_from,
        valid_until=metadata.valid_until,
        days_until_expiry=days,
        expired=expired,
        self_signed=metadata.self_signed,
        status=status,
        error=verification_error,
        tls_version=observation.tls_version,
        cipher=observation.cipher,
        cipher_bits=observation.cipher_bits,
        certificate_verified=certificate_verified,
        verification_error=verification_error,
    )


def _collect_tls_observation(
    hostname: str,
    timeout: float,
    context: ssl.SSLContext,
    connect_host: str | None = None,
    port: int = 443,
) -> _TlsObservation:
    with socket.create_connection((connect_host or hostname, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
            cipher_data = tls_socket.cipher()
            return _TlsObservation(
                certificate=tls_socket.getpeercert() or {},
                certificate_der=tls_socket.getpeercert(binary_form=True),
                tls_version=tls_socket.version(),
                cipher=cipher_data[0] if cipher_data else None,
                cipher_bits=cipher_data[2] if cipher_data else None,
            )


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _verification_error_details(exc: ssl.SSLCertVerificationError) -> tuple[int | None, str]:
    verify_code = getattr(exc, "verify_code", None)
    verify_message = getattr(exc, "verify_message", None) or str(exc)
    return verify_code, str(verify_message)


def check_ssl(
    hostname: str,
    timeout: float = 3.0,
    connect_host: str | None = None,
    port: int = 443,
) -> SslCheckResult:
    context = ssl.create_default_context()
    try:
        observation = _collect_tls_observation(hostname, timeout, context, connect_host, port)
        metadata = (
            _metadata_from_stdlib(observation.certificate)
            if observation.certificate
            else _metadata_from_der(observation.certificate_der or b"")
        )
        return _build_result(metadata, observation, certificate_verified=True)
    except ssl.SSLCertVerificationError as exc:
        verify_code, verify_message = _verification_error_details(exc)
        try:
            observation = _collect_tls_observation(hostname, timeout, _unverified_context(), connect_host, port)
            metadata = _metadata_from_der(observation.certificate_der or b"")
        except Exception as recovery_exc:
            status = _classify_verification_failure(verify_code, verify_message)
            return _empty_result(status, f"{verify_message}; certificate metadata recovery failed: {recovery_exc}")

        days = _days_until(metadata.valid_until)
        expired = days < 0 if days is not None else None
        status = _classify_verification_failure(
            verify_code,
            verify_message,
            expired=expired,
            self_signed=metadata.self_signed,
        )
        return _build_result(
            metadata,
            observation,
            certificate_verified=False,
            verification_error=verify_message,
            verification_status=status,
        )
    except socket.timeout as exc:
        return _empty_result("timeout", str(exc) or "TLS connection timed out.")
    except ConnectionRefusedError as exc:
        return _empty_result("unreachable", str(exc) or "TLS connection was refused.")
    except ssl.SSLError as exc:
        return _empty_result("tls_error", str(exc))
    except OSError as exc:
        return _empty_result("unreachable", str(exc))
    except Exception as exc:
        return _empty_result("unknown", str(exc))
