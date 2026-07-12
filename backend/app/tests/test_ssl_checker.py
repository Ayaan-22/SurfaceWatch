import ssl
from datetime import datetime, timedelta, timezone

from app.scanner import ssl_checker


def test_verification_failure_classification_is_stable() -> None:
    assert ssl_checker._classify_verification_failure(10, "certificate has expired") == "expired"
    assert ssl_checker._classify_verification_failure(18, "self signed certificate") == "self_signed"
    assert ssl_checker._classify_verification_failure(62, "hostname mismatch") == "hostname_mismatch"
    assert ssl_checker._classify_verification_failure(20, "unable to get local issuer certificate") == "untrusted"
    assert ssl_checker._classify_verification_failure(9, "certificate is not yet valid") == "not_yet_valid"
    assert ssl_checker._classify_verification_failure(23, "certificate revoked") == "revoked"


def test_verification_classification_uses_metadata_when_codes_are_unavailable() -> None:
    assert ssl_checker._classify_verification_failure(None, "verification failed", expired=True) == "expired"
    assert ssl_checker._classify_verification_failure(None, "verification failed", self_signed=True) == "self_signed"
    assert ssl_checker._classify_verification_failure(None, "certificate is not valid for api.example.org") == "hostname_mismatch"


def test_certificate_health_classifies_expiry_and_self_signed() -> None:
    assert ssl_checker._classify_certificate_health(-1, False) == "expired"
    assert ssl_checker._classify_certificate_health(90, True) == "self_signed"
    assert ssl_checker._classify_certificate_health(30, False) == "expiring_soon"
    assert ssl_checker._classify_certificate_health(31, False) == "healthy"


def test_parse_cert_time_returns_none_for_malformed_values() -> None:
    assert ssl_checker._parse_cert_time("Jul 10 12:00:00 2027 GMT") == datetime(
        2027, 7, 10, 12, 0, tzinfo=timezone.utc
    )
    assert ssl_checker._parse_cert_time("not a certificate date") is None


def test_check_ssl_captures_negotiated_tls_and_cipher(monkeypatch) -> None:
    future = datetime.now(timezone.utc) + timedelta(days=90)
    certificate = {
        "issuer": ((('organizationName', 'Example CA'),),),
        "subject": ((('commonName', 'example.org'),),),
        "subjectAltName": (("DNS", "example.org"), ("DNS", "www.example.org")),
        "notBefore": "Jul 10 00:00:00 2026 GMT",
        "notAfter": future.strftime("%b %d %H:%M:%S %Y GMT"),
    }
    observation = ssl_checker._TlsObservation(
        certificate=certificate,
        certificate_der=b"unused",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
    )
    monkeypatch.setattr(ssl_checker, "_collect_tls_observation", lambda *args, **kwargs: observation)

    result = ssl_checker.check_ssl("example.org", timeout=0.1)

    assert result.status == "healthy"
    assert result.certificate_verified is True
    assert result.tls_version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.cipher_bits == 256
    assert result.subject_alt_names == ["example.org", "www.example.org"]


def test_check_ssl_recovers_expired_certificate_metadata_after_verification_failure(monkeypatch) -> None:
    verification_error = ssl.SSLCertVerificationError(1, "certificate has expired")
    verification_error.verify_code = 10
    verification_error.verify_message = "certificate has expired"
    recovered_observation = ssl_checker._TlsObservation(
        certificate={},
        certificate_der=b"certificate-der",
        tls_version="TLSv1.2",
        cipher="ECDHE-RSA-AES256-GCM-SHA384",
        cipher_bits=256,
    )
    calls = {"count": 0}

    def collect(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            raise verification_error
        return recovered_observation

    expired_at = datetime.now(timezone.utc) - timedelta(days=2)
    metadata = ssl_checker._CertificateMetadata(
        issuer="CN=Example CA",
        subject_common_name="example.org",
        subject_alt_names=("example.org",),
        valid_from=datetime.now(timezone.utc) - timedelta(days=365),
        valid_until=expired_at,
        self_signed=False,
    )
    monkeypatch.setattr(ssl_checker, "_collect_tls_observation", collect)
    monkeypatch.setattr(ssl_checker, "_metadata_from_der", lambda value: metadata)

    result = ssl_checker.check_ssl("example.org", timeout=0.1)

    assert calls["count"] == 2
    assert result.status == "expired"
    assert result.expired is True
    assert result.certificate_verified is False
    assert result.verification_error == "certificate has expired"
    assert result.tls_version == "TLSv1.2"
    assert result.subject_common_name == "example.org"
