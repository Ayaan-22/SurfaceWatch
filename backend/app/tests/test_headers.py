from app.scanner.headers import analyze_headers


def _by_name(headers: dict[str, str]) -> dict[str, dict]:
    results = analyze_headers(headers)
    names = [row["header_name"] for row in results]
    assert len(names) == len(set(names)), "Each header must have one canonical analysis row."
    return {row["header_name"]: row for row in results}


def test_missing_headers_generate_backward_compatible_risk_results() -> None:
    by_name = _by_name({})

    assert by_name["strict-transport-security"]["present"] is False
    assert by_name["content-security-policy"]["risk_level"] == "medium"
    assert by_name["content-security-policy"]["issue"] is True
    assert by_name["content-security-policy"]["title"] == "Missing Content-Security-Policy header"
    assert by_name["content-security-policy"]["rule_id"] == "headers.missing_content_security_policy"
    for row in by_name.values():
        assert {"header_name", "present", "value", "risk_level", "recommendation"} <= row.keys()


def test_weak_header_values_emit_one_explicit_issue_per_header() -> None:
    by_name = _by_name(
        {
            "Strict-Transport-Security": "max-age=60",
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
            "X-Frame-Options": "ALLOW-FROM https://example.org",
            "X-Content-Type-Options": "sniff",
            "Referrer-Policy": "made-up-policy",
            "Permissions-Policy": " ",
        }
    )

    assert by_name["strict-transport-security"]["issue"] is True
    assert by_name["content-security-policy"]["issue"] is True
    assert by_name["content-security-policy"]["risk_level"] == "medium"
    assert "wildcard" in " ".join(by_name["content-security-policy"]["details"])
    assert by_name["x-frame-options"]["title"] == "Invalid X-Frame-Options header"
    assert by_name["x-content-type-options"]["issue"] is True
    assert by_name["referrer-policy"]["issue"] is True
    assert by_name["permissions-policy"]["issue"] is True


def test_strong_header_values_are_marked_compliant() -> None:
    by_name = _by_name(
        {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        }
    )

    assert all(row["issue"] is False for row in by_name.values())
    assert all(row["recommendation"] is None for row in by_name.values())


def test_exposed_implementation_headers_are_explicit_issues() -> None:
    by_name = _by_name({"Server": "nginx/1.24", "X-Powered-By": "Express"})

    assert by_name["server"]["issue"] is True
    assert by_name["server"]["risk_level"] == "low"
    assert by_name["x-powered-by"]["title"] == "X-Powered-By header exposes implementation details"


def test_permissive_cors_and_credentials_are_flagged() -> None:
    by_name = _by_name(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

    cors = by_name["access-control-allow-origin"]
    assert cors["issue"] is True
    assert cors["risk_level"] == "medium"
    assert cors["rule_id"] == "cors.origin_policy"


def test_cookie_flags_are_checked_without_persisting_cookie_secrets() -> None:
    by_name = _by_name(
        {
            "Set-Cookie": (
                "session=top-secret; Path=/; HttpOnly, "
                "prefs=also-secret; Expires=Wed, 21 Oct 2030 07:28:00 GMT; Secure; SameSite=Lax"
            )
        }
    )

    cookie = by_name["set-cookie"]
    assert cookie["issue"] is True
    assert cookie["risk_level"] == "medium"
    assert "session" in cookie["value"]
    assert "prefs" in cookie["value"]
    assert "top-secret" not in cookie["value"]
    assert any("Secure" in detail for detail in cookie["details"])
    assert any("HttpOnly" in detail for detail in cookie["details"])


def test_secure_cookie_is_marked_compliant() -> None:
    by_name = _by_name({"Set-Cookie": "session=secret; Secure; HttpOnly; SameSite=Lax"})

    assert by_name["set-cookie"]["issue"] is False
    assert by_name["set-cookie"]["risk_level"] == "info"
