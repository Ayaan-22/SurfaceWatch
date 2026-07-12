from app.scanner import http_probe
from app.scanner.http_probe import HttpProbeResult, _pinned_connection_url, _redirect_is_in_scope, http_targets


def test_http_targets_include_confirmed_alternate_web_ports_without_duplicates() -> None:
    assert http_targets("example.org", [80, 443, 8080, 8443, 8080, 22]) == [
        "https://example.org",
        "http://example.org",
        "http://example.org:8080",
        "https://example.org:8443",
    ]


def test_redirect_scope_rejects_cross_host_and_non_http_destinations() -> None:
    assert _redirect_is_in_scope("https://example.org/login", "example.org")
    assert not _redirect_is_in_scope("https://accounts.example.net/login", "example.org")
    assert not _redirect_is_in_scope("file:///etc/passwd", "example.org")


def test_pinned_connection_url_preserves_virtual_host_and_port() -> None:
    assert _pinned_connection_url("https://example.org:8443/admin?q=1", "2001:4860:4860::8888") == (
        "https://[2001:4860:4860::8888]:8443/admin?q=1",
        "example.org:8443",
    )


def test_invalid_tls_fallback_preserves_verification_error_and_response(monkeypatch) -> None:
    calls: list[bool] = []

    def fake_probe(*args, **kwargs):
        verify_tls = args[-1]
        calls.append(verify_tls)
        if verify_tls:
            return HttpProbeResult(
                url="https://example.org",
                requested_url="https://example.org",
                status_code=None,
                headers={},
                body_preview="",
                error="[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed",
            )
        return HttpProbeResult(
            url="https://example.org",
            requested_url="https://example.org",
            status_code=200,
            headers={"server": "nginx"},
            body_preview="ok",
            tls_verified=False,
        )

    monkeypatch.setattr(http_probe, "probe_url", fake_probe)

    result = http_probe.probe_url_resilient("https://example.org", "example.org", 1, 1024, 2, "93.184.216.34")

    assert calls == [True, False]
    assert result.status_code == 200
    assert result.tls_verified is False
    assert "TLS verification failed" in (result.error or "")
