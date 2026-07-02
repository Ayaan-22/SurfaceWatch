from app.scanner.headers import analyze_headers


def test_missing_headers_generate_risk_results() -> None:
    results = analyze_headers({})
    by_name = {row["header_name"]: row for row in results}
    assert by_name["strict-transport-security"]["present"] is False
    assert by_name["content-security-policy"]["risk_level"] == "medium"


def test_exposed_powered_by_is_flagged() -> None:
    results = analyze_headers({"X-Powered-By": "Express"})
    assert any(row["header_name"] == "x-powered-by" and row["risk_level"] == "low" for row in results)
