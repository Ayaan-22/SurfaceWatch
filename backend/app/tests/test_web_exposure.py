from app.scanner.http_probe import HttpProbeResult
from app.scanner.web_exposure import WebExposureProbeResult, analyze_web_exposures


def test_analyze_web_exposures_detects_exposed_env_file() -> None:
    findings = analyze_web_exposures(
        [],
        [
            WebExposureProbeResult(
                url="https://example.org/.env",
                path="/.env",
                status_code=200,
                headers={"content-type": "text/plain"},
                body_preview="SECRET_KEY=abc\nDATABASE_URL=postgres://example",
            )
        ],
    )

    assert [finding.title for finding in findings] == ["Environment file exposed"]
    assert findings[0].severity == "critical"


def test_analyze_web_exposures_detects_directory_listing_and_5xx() -> None:
    findings = analyze_web_exposures(
        [
            HttpProbeResult(
                url="https://example.org/",
                status_code=503,
                headers={},
                body_preview="Service unavailable",
            ),
            HttpProbeResult(
                url="https://example.org/uploads/",
                status_code=200,
                headers={},
                body_preview="<title>Index of /uploads/</title>",
            )
        ],
        [],
    )

    titles = {finding.title for finding in findings}
    assert "Public endpoint returns server error" in titles
    assert "Directory listing exposed" in titles
