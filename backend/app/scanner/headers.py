import re
from typing import TypedDict


class HeaderAnalysisResult(TypedDict):
    # Keep the original keys stable because the orchestrator and API persist them.
    header_name: str
    present: bool
    value: str | None
    risk_level: str
    recommendation: str | None
    # Structured metadata lets callers distinguish presence from compliance.
    issue: bool
    title: str | None
    rule_id: str
    details: list[str]


REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "medium",
        "title": "Missing Strict-Transport-Security header",
        "recommendation": "Add HSTS with a reasonable max-age after confirming HTTPS works everywhere.",
    },
    "content-security-policy": {
        "severity": "medium",
        "title": "Missing Content-Security-Policy header",
        "recommendation": "Add a restrictive Content-Security-Policy and avoid broad wildcards.",
    },
    "x-frame-options": {
        "severity": "low",
        "title": "Missing clickjacking protection header",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    },
    "x-content-type-options": {
        "severity": "low",
        "title": "Missing MIME-sniffing protection header",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "severity": "info",
        "title": "Missing Referrer-Policy header",
        "recommendation": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
    },
    "permissions-policy": {
        "severity": "info",
        "title": "Missing Permissions-Policy header",
        "recommendation": "Set Permissions-Policy to limit powerful browser features.",
    },
}


_HSTS_MIN_MAX_AGE = 15_552_000  # 180 days
_HSTS_MAX_AGE_RE = re.compile(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", re.IGNORECASE)
_COOKIE_SPLIT_RE = re.compile(r",(?=\s*[^=;,\s]+\s*=)")
_VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def _result(
    header_name: str,
    present: bool,
    value: str | None,
    risk_level: str,
    recommendation: str | None,
    *,
    issue: bool,
    title: str | None,
    rule_id: str,
    details: list[str] | None = None,
) -> HeaderAnalysisResult:
    return {
        "header_name": header_name,
        "present": present,
        "value": value,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "issue": issue,
        "title": title,
        "rule_id": rule_id,
        "details": details or [],
    }


def _validate_hsts(value: str) -> tuple[bool, str, str | None, list[str]]:
    match = _HSTS_MAX_AGE_RE.search(value)
    if match is None:
        return (
            True,
            "medium",
            "Set a numeric max-age directive of at least 15552000 seconds after confirming HTTPS is reliable.",
            ["The max-age directive is missing or invalid."],
        )

    max_age = int(match.group(1))
    if max_age < _HSTS_MIN_MAX_AGE:
        return (
            True,
            "medium",
            "Increase the HSTS max-age to at least 15552000 seconds after confirming HTTPS is reliable.",
            [f"max-age is {max_age}; the scanner baseline is {_HSTS_MIN_MAX_AGE}."],
        )
    return False, "info", None, []


def _validate_csp(value: str) -> tuple[bool, str, str | None, list[str]]:
    directives = [part.strip().lower() for part in value.split(";") if part.strip()]
    tokens = [token for directive in directives for token in directive.split()[1:]]
    details: list[str] = []

    if not directives:
        details.append("The policy is empty.")
    if "*" in tokens:
        details.append("The policy contains an unrestricted wildcard source.")
    if "'unsafe-eval'" in tokens:
        details.append("script execution allows 'unsafe-eval'.")
    if "'unsafe-inline'" in tokens:
        details.append("inline script or style execution allows 'unsafe-inline'.")

    if details:
        return (
            True,
            "medium",
            "Replace broad CSP sources with explicit origins and use nonces or hashes for required inline code.",
            details,
        )
    return False, "info", None, []


def _validate_x_frame_options(value: str) -> tuple[bool, str, str | None, list[str]]:
    if value.strip().upper() in {"DENY", "SAMEORIGIN"}:
        return False, "info", None, []
    return (
        True,
        "low",
        "Set X-Frame-Options to DENY or SAMEORIGIN, or enforce CSP frame-ancestors.",
        ["The header value is not DENY or SAMEORIGIN."],
    )


def _validate_nosniff(value: str) -> tuple[bool, str, str | None, list[str]]:
    if value.strip().lower() == "nosniff":
        return False, "info", None, []
    return True, "low", "Set X-Content-Type-Options exactly to nosniff.", ["The header value is not nosniff."]


def _validate_referrer_policy(value: str) -> tuple[bool, str, str | None, list[str]]:
    policies = [part.strip().lower() for part in value.split(",") if part.strip()]
    if policies and all(policy in _VALID_REFERRER_POLICIES for policy in policies):
        return False, "info", None, []
    return (
        True,
        "info",
        "Use a valid Referrer-Policy such as strict-origin-when-cross-origin or no-referrer.",
        ["The header contains an empty or unrecognized policy value."],
    )


def _validate_permissions_policy(value: str) -> tuple[bool, str, str | None, list[str]]:
    if value.strip():
        return False, "info", None, []
    return (
        True,
        "info",
        "Define an explicit Permissions-Policy that disables browser features the application does not need.",
        ["The header is empty."],
    )


def _analyze_cors(headers: dict[str, str]) -> HeaderAnalysisResult | None:
    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    if origin is None:
        if not credentials:
            return None
        return _result(
            "access-control-allow-credentials",
            True,
            headers.get("access-control-allow-credentials"),
            "low",
            "Return Access-Control-Allow-Credentials only with a narrowly allowlisted origin.",
            issue=True,
            title="CORS credentials enabled without an explicit origin",
            rule_id="cors.credentials_without_origin",
            details=["Credentials are enabled but no Access-Control-Allow-Origin value was observed."],
        )

    normalized_origin = origin.strip()
    details: list[str] = []
    severity = "low"
    if normalized_origin == "*":
        details.append("Access-Control-Allow-Origin permits every origin.")
        if credentials:
            severity = "medium"
            details.append("Access-Control-Allow-Credentials is also enabled; this combination is invalid and unsafe to rely on.")
    elif normalized_origin.lower() == "null":
        severity = "medium"
        details.append("The opaque null origin is allowed.")
    elif "," in normalized_origin or " " in normalized_origin:
        severity = "medium"
        details.append("The header contains multiple or malformed origin values.")
    elif "origin" not in {item.strip().lower() for item in headers.get("vary", "").split(",")}:
        details.append("A specific origin is returned without Vary: Origin, which can make shared caches unsafe.")

    return _result(
        "access-control-allow-origin",
        True,
        origin,
        severity if details else "info",
        "Use an explicit origin allowlist, emit one valid origin, and add Vary: Origin for dynamic CORS responses."
        if details
        else None,
        issue=bool(details),
        title="Permissive or invalid CORS policy" if details else None,
        rule_id="cors.origin_policy",
        details=details,
    )


def _split_set_cookie(value: str) -> list[str]:
    cookies: list[str] = []
    for line in value.replace("\r\n", "\n").splitlines():
        cookies.extend(part.strip() for part in _COOKIE_SPLIT_RE.split(line) if part.strip())
    return cookies


def _analyze_cookies(value: str) -> HeaderAnalysisResult:
    cookies = _split_set_cookie(value)
    details: list[str] = []
    cookie_names: list[str] = []
    severity = "low"

    for cookie in cookies:
        parts = [part.strip() for part in cookie.split(";") if part.strip()]
        if not parts or "=" not in parts[0]:
            continue
        cookie_name = parts[0].split("=", 1)[0].strip() or "<unnamed>"
        cookie_names.append(cookie_name)
        attributes = {part.split("=", 1)[0].strip().lower(): part for part in parts[1:]}
        missing: list[str] = []
        if "secure" not in attributes:
            missing.append("Secure")
            severity = "medium"
        if "httponly" not in attributes:
            missing.append("HttpOnly")
            severity = "medium"
        if "samesite" not in attributes:
            missing.append("SameSite")
        if missing:
            details.append(f"Cookie {cookie_name!r} is missing {', '.join(missing)}.")

    redacted_value = f"cookies: {', '.join(cookie_names)} (values redacted)" if cookie_names else "cookie values redacted"
    return _result(
        "set-cookie",
        True,
        redacted_value,
        severity if details else "info",
        "Set Secure, HttpOnly, and an appropriate SameSite attribute on sensitive cookies." if details else None,
        issue=bool(details),
        title="Cookie security attributes missing" if details else None,
        rule_id="cookies.security_attributes",
        details=details,
    )


def analyze_headers(headers: dict[str, str], *, is_https: bool = True) -> list[HeaderAnalysisResult]:
    normalized = {key.strip().lower(): str(value).strip() for key, value in headers.items()}
    results: dict[str, HeaderAnalysisResult] = {}

    validators = {
        "strict-transport-security": (_validate_hsts, "headers.hsts", "Weak Strict-Transport-Security header"),
        "content-security-policy": (_validate_csp, "headers.csp", "Weak Content-Security-Policy header"),
        "x-frame-options": (_validate_x_frame_options, "headers.x_frame_options", "Invalid X-Frame-Options header"),
        "x-content-type-options": (_validate_nosniff, "headers.nosniff", "Invalid X-Content-Type-Options header"),
        "referrer-policy": (_validate_referrer_policy, "headers.referrer_policy", "Invalid Referrer-Policy header"),
        "permissions-policy": (_validate_permissions_policy, "headers.permissions_policy", "Empty Permissions-Policy header"),
    }

    for header_name, metadata in REQUIRED_HEADERS.items():
        if header_name == "strict-transport-security" and not is_https:
            continue
        value = normalized.get(header_name)
        if value is None:
            results[header_name] = _result(
                header_name,
                False,
                None,
                metadata["severity"],
                metadata["recommendation"],
                issue=True,
                title=metadata["title"],
                rule_id=f"headers.missing_{header_name.replace('-', '_')}",
            )
            continue

        validator, rule_id, invalid_title = validators[header_name]
        issue, severity, recommendation, details = validator(value)
        results[header_name] = _result(
            header_name,
            True,
            value,
            severity,
            recommendation,
            issue=issue,
            title=invalid_title if issue else None,
            rule_id=rule_id,
            details=details,
        )

    for exposed_header, title in (
        ("server", "Server header exposes implementation details"),
        ("x-powered-by", "X-Powered-By header exposes implementation details"),
    ):
        value = normalized.get(exposed_header)
        if value:
            results[exposed_header] = _result(
                exposed_header,
                True,
                value,
                "low",
                f"Suppress or minimize the {exposed_header} header where possible.",
                issue=True,
                title=title,
                rule_id=f"headers.exposed_{exposed_header.replace('-', '_')}",
                details=["A public response identifies server-side implementation details."],
            )

    cors_result = _analyze_cors(normalized)
    if cors_result is not None:
        results[cors_result["header_name"]] = cors_result

    set_cookie = normalized.get("set-cookie")
    if set_cookie:
        results["set-cookie"] = _analyze_cookies(set_cookie)

    return list(results.values())
