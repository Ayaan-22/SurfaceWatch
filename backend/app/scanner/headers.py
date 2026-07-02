REQUIRED_HEADERS = {
    "strict-transport-security": {
        "severity": "medium",
        "recommendation": "Add HSTS with a reasonable max-age after confirming HTTPS works everywhere.",
    },
    "content-security-policy": {
        "severity": "medium",
        "recommendation": "Add a restrictive Content-Security-Policy and avoid broad wildcards.",
    },
    "x-frame-options": {
        "severity": "low",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
    },
    "x-content-type-options": {
        "severity": "low",
        "recommendation": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "severity": "info",
        "recommendation": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
    },
    "permissions-policy": {
        "severity": "info",
        "recommendation": "Set Permissions-Policy to limit powerful browser features.",
    },
}


def analyze_headers(headers: dict[str, str]) -> list[dict[str, str | bool | None]]:
    normalized = {key.lower(): value for key, value in headers.items()}
    results: list[dict[str, str | bool | None]] = []

    for header_name, metadata in REQUIRED_HEADERS.items():
        value = normalized.get(header_name)
        results.append(
            {
                "header_name": header_name,
                "present": value is not None,
                "value": value,
                "risk_level": "info" if value else metadata["severity"],
                "recommendation": None if value else metadata["recommendation"],
            }
        )

    for exposed_header in ("server", "x-powered-by"):
        value = normalized.get(exposed_header)
        if value:
            results.append(
                {
                    "header_name": exposed_header,
                    "present": True,
                    "value": value,
                    "risk_level": "low",
                    "recommendation": f"Suppress or minimize the {exposed_header} header where possible.",
                }
            )

    csp = normalized.get("content-security-policy", "")
    if csp and ("*" in csp or "unsafe-inline" in csp):
        results.append(
            {
                "header_name": "content-security-policy",
                "present": True,
                "value": csp,
                "risk_level": "low",
                "recommendation": "Review broad CSP allowances such as wildcards or unsafe-inline.",
            }
        )
    return results
