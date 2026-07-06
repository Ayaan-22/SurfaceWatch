from dataclasses import dataclass

import httpx

from app.scanner.http_probe import HttpProbeResult


AGGRESSIVE_EXPOSURE_PATHS = [
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/wp-config.php~",
    "/phpinfo.php",
    "/server-status",
    "/uploads/",
    "/backup/",
    "/admin/",
]


@dataclass(frozen=True)
class WebExposureProbeResult:
    url: str
    path: str
    status_code: int | None
    headers: dict[str, str]
    body_preview: str
    error: str | None = None


@dataclass(frozen=True)
class WebExposureFinding:
    title: str
    description: str
    severity: str
    category: str
    evidence: dict
    business_impact: str
    recommendation: str


def probe_web_exposure_paths(hostname: str, paths: list[str], timeout: float = 3.0) -> list[WebExposureProbeResult]:
    results: list[WebExposureProbeResult] = []
    for scheme in ("https", "http"):
        for path in paths:
            normalized_path = path if path.startswith("/") else f"/{path}"
            url = f"{scheme}://{hostname}{normalized_path}"
            try:
                response = httpx.get(url, follow_redirects=True, timeout=timeout)
                body = response.text[:5000]
                results.append(
                    WebExposureProbeResult(
                        url=str(response.url),
                        path=normalized_path,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body_preview=body,
                    )
                )
            except httpx.HTTPError as exc:
                results.append(
                    WebExposureProbeResult(
                        url=url,
                        path=normalized_path,
                        status_code=None,
                        headers={},
                        body_preview="",
                        error=str(exc),
                    )
                )
    return results


def analyze_web_exposures(
    http_results: list[HttpProbeResult],
    exposure_results: list[WebExposureProbeResult],
) -> list[WebExposureFinding]:
    findings: list[WebExposureFinding] = []
    seen: set[tuple[str, str]] = set()

    for result in http_results:
        if result.status_code is not None and result.status_code >= 500:
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Public endpoint returns server error",
                    description="The public web endpoint returned a 5xx response during scanning.",
                    severity="medium",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code},
                    business_impact="Server errors can reveal unstable deployments and may expose debugging information.",
                    recommendation="Review application logs and fix the server-side error path.",
                ),
            )
        _maybe_directory_listing(findings, seen, result.url, result.status_code, result.body_preview)

    for result in exposure_results:
        if result.status_code is None:
            continue
        _maybe_directory_listing(findings, seen, result.url, result.status_code, result.body_preview)
        if result.status_code not in {200, 206}:
            continue

        path = result.path.lower()
        body = result.body_preview.lower()
        content_type = result.headers.get("content-type", "").lower()

        if path == "/.env" and ("=" in result.body_preview or "secret" in body or "password" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Environment file exposed",
                    description="A common environment configuration file appears to be publicly reachable.",
                    severity="critical",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Exposed environment files can leak credentials, API keys, and infrastructure details.",
                    recommendation="Remove the file from the web root and rotate any secrets that may have been exposed.",
                ),
            )
        elif path == "/.git/config" and "[core]" in body:
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Git metadata exposed",
                    description="A public .git configuration file appears to be reachable.",
                    severity="high",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Exposed repository metadata can allow source disclosure and accelerate targeted attacks.",
                    recommendation="Block access to VCS directories and remove repository metadata from deployed web roots.",
                ),
            )
        elif path.endswith(".sql") and ("insert into" in body or "create table" in body or "dump" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Database dump exposed",
                    description="A common database dump path appears to be publicly reachable.",
                    severity="critical",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Database dumps can expose customer data, password hashes, and internal application structure.",
                    recommendation="Remove public dump files, investigate access logs, and rotate affected credentials.",
                ),
            )
        elif path in {"/backup.zip", "/backup.tar.gz"} and ("zip" in content_type or "gzip" in content_type or "octet-stream" in content_type):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Backup archive exposed",
                    description="A common backup archive path returned downloadable archive-like content.",
                    severity="high",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path, "content_type": content_type},
                    business_impact="Backup archives may disclose source code, credentials, and customer data.",
                    recommendation="Remove public backup files and store backups outside the web root.",
                ),
            )
        elif path == "/phpinfo.php" and "php version" in body:
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="phpinfo page exposed",
                    description="A phpinfo diagnostic page appears to be publicly reachable.",
                    severity="medium",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Diagnostic pages can reveal versions, paths, modules, and environment details useful to attackers.",
                    recommendation="Remove diagnostic pages from public environments.",
                ),
            )
        elif path == "/server-status" and ("server status" in body or "apache status" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Server status page exposed",
                    description="A server status endpoint appears to be publicly reachable.",
                    severity="medium",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Status pages can reveal request patterns, backend paths, and operational metadata.",
                    recommendation="Restrict status endpoints to trusted administration networks.",
                ),
            )

    return findings


def _maybe_directory_listing(
    findings: list[WebExposureFinding],
    seen: set[tuple[str, str]],
    url: str,
    status_code: int | None,
    body_preview: str,
) -> None:
    body = body_preview.lower()
    if status_code == 200 and ("index of /" in body or "<title>index of" in body):
        _append_unique(
            findings,
            seen,
            WebExposureFinding(
                title="Directory listing exposed",
                description="A public web path appears to expose an auto-generated directory listing.",
                severity="high",
                category="Web Exposure",
                evidence={"url": url, "status_code": status_code},
                business_impact="Directory listings can expose backups, source files, uploads, and internal filenames.",
                recommendation="Disable directory indexing and review public file storage permissions.",
            ),
        )


def _append_unique(findings: list[WebExposureFinding], seen: set[tuple[str, str]], finding: WebExposureFinding) -> None:
    key = (finding.title, str(finding.evidence.get("url", "")))
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)
