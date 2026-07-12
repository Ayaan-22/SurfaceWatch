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


def test_analyze_web_exposures_detects_cloud_credentials_and_diagnostics() -> None:
    findings = analyze_web_exposures(
        [],
        [
            WebExposureProbeResult(
                url="https://example.org/.aws/credentials",
                path="/.aws/credentials",
                status_code=200,
                headers={"content-type": "text/plain"},
                body_preview="[default]\naws_access_key_id=AKIA_REDACTED\naws_secret_access_key=redacted",
            ),
            WebExposureProbeResult(
                url="https://example.org/actuator/env",
                path="/actuator/env",
                status_code=200,
                headers={"content-type": "application/json"},
                body_preview='{"activeProfiles":["production"],"propertySources":[]}',
            ),
            WebExposureProbeResult(
                url="https://example.org/metrics",
                path="/metrics",
                status_code=200,
                headers={"content-type": "text/plain"},
                body_preview="# HELP process_cpu_seconds CPU time\n# TYPE process_cpu_seconds counter",
            ),
        ],
    )

    by_title = {finding.title: finding for finding in findings}
    assert by_title["Cloud credentials exposed"].severity == "critical"
    assert by_title["Application environment endpoint exposed"].severity == "high"
    assert by_title["Metrics endpoint exposed"].severity == "medium"
