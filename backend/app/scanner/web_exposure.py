import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from app.scanner.http_probe import HttpProbeResult, probe_url_resilient


AGGRESSIVE_EXPOSURE_PATHS = [
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/.aws/credentials",
    "/.docker/config.json",
    "/.npmrc",
    "/.htpasswd",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/config.php",
    "/wp-config.php~",
    "/web.config",
    "/package.json",
    "/composer.json",
    "/phpinfo.php",
    "/server-status",
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/actuator/env",
    "/actuator/heapdump",
    "/metrics",
    "/debug/pprof/",
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
    requested_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    response_time_ms: int | None = None
    content_length: int | None = None
    tls_verified: bool | None = None


@dataclass(frozen=True)
class WebExposureFinding:
    title: str
    description: str
    severity: str
    category: str
    evidence: dict
    business_impact: str
    recommendation: str


def probe_web_exposure_paths(
    hostname: str,
    paths: list[str],
    timeout: float = 3.0,
    base_urls: list[str] | None = None,
    concurrency: int = 10,
    max_body_bytes: int = 65536,
    max_base_urls: int = 6,
    connect_ip: str | None = None,
) -> list[WebExposureProbeResult]:
    """Probe the declared safe path set concurrently and retain every outcome."""
    bases = list(dict.fromkeys(base_urls or [f"https://{hostname}", f"http://{hostname}"]))[:max_base_urls]
    targets: list[tuple[str, str]] = []
    for base_url in bases:
        for path in paths:
            normalized_path = path if path.startswith("/") else f"/{path}"
            targets.append((urljoin(f"{base_url.rstrip('/')}/", normalized_path.lstrip("/")), normalized_path))
    if not targets:
        return []

    max_workers = max(1, min(concurrency, len(targets)))
    by_target: dict[tuple[str, str], WebExposureProbeResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="web-exposure") as pool:
        future_to_target = {
            pool.submit(
                probe_url_resilient,
                url,
                urlsplit(url).hostname or hostname,
                timeout,
                max_body_bytes,
                3,
                connect_ip,
            ): (url, path)
            for url, path in targets
        }
        for future in as_completed(future_to_target):
            url, path = future_to_target[future]
            try:
                result = future.result()
                by_target[(url, path)] = WebExposureProbeResult(
                    url=result.url,
                    requested_url=result.requested_url,
                    path=path,
                    status_code=result.status_code,
                    headers=result.headers,
                    body_preview=result.body_preview,
                    error=result.error,
                    redirect_chain=result.redirect_chain,
                    response_time_ms=result.response_time_ms,
                    content_length=result.content_length,
                    tls_verified=result.tls_verified,
                )
            except Exception as exc:  # Defensive: preserve the planned path row.
                by_target[(url, path)] = WebExposureProbeResult(
                    url=url,
                    requested_url=url,
                    path=path,
                    status_code=None,
                    headers={},
                    body_preview="",
                    error=str(exc),
                )
    return [by_target[target] for target in targets]


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
        normalized_headers = {key.lower(): value for key, value in result.headers.items()}
        content_type = normalized_headers.get("content-type", "").lower()

        if path == "/.env" and _looks_like_environment_file(result.body_preview):
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
        elif path == "/.svn/entries" and ("dir" in body or "svn" in body or body.strip().isdigit()):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Subversion metadata exposed",
                    description="Public Subversion working-copy metadata appears to be reachable.",
                    severity="high",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Version-control metadata can disclose source paths, repository locations, and application history.",
                    recommendation="Block VCS metadata paths and deploy from clean build artifacts.",
                ),
            )
        elif path == "/.ds_store" and ("bud1" in body or "octet-stream" in content_type):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Finder metadata exposed",
                    description="A public .DS_Store file appears to be reachable.",
                    severity="medium",
                    category="Web Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Finder metadata may disclose hidden filenames and directory structure.",
                    recommendation="Remove .DS_Store files from deployments and block dotfile access.",
                ),
            )
        elif path == "/.aws/credentials" and ("aws_access_key_id" in body or "aws_secret_access_key" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Cloud credentials exposed",
                    description="An AWS credentials file appears to be publicly reachable.",
                    severity="critical",
                    category="Secret Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Exposed cloud credentials can enable data theft, infrastructure takeover, and fraudulent resource use.",
                    recommendation="Remove the file immediately, revoke the exposed keys, and investigate access logs.",
                ),
            )
        elif path == "/.docker/config.json" and '"auths"' in body and ("auth" in body or "credsstore" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Container registry credentials exposed",
                    description="A Docker client configuration containing authentication metadata appears public.",
                    severity="critical",
                    category="Secret Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Registry credentials can expose private images and software supply-chain assets.",
                    recommendation="Remove the file, revoke registry credentials, and review image access logs.",
                ),
            )
        elif path == "/.npmrc" and ("_authtoken" in body or "//registry" in body and ":_auth" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Package registry token exposed",
                    description="An npm configuration file containing authentication material appears public.",
                    severity="critical",
                    category="Secret Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="A stolen registry token can expose private packages or enable malicious package publication.",
                    recommendation="Remove the file, revoke the token, and audit recent registry activity.",
                ),
            )
        elif path == "/.htpasswd" and ":$" in body:
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Password hash file exposed",
                    description="An HTTP basic-auth password file appears to be publicly reachable.",
                    severity="critical",
                    category="Secret Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Exposed password hashes can be cracked offline and reused against administrative services.",
                    recommendation="Block dotfiles, remove the file from the web root, and rotate affected credentials.",
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
        elif path in {"/config.php", "/wp-config.php~", "/web.config"} and _looks_like_sensitive_config(body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Application configuration exposed",
                    description="A public application configuration or backup file appears to contain sensitive settings.",
                    severity="critical",
                    category="Secret Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Configuration disclosure can reveal database credentials, signing secrets, and internal service locations.",
                    recommendation="Remove configuration files from the web root and rotate any disclosed secrets.",
                ),
            )
        elif path in {"/package.json", "/composer.json"} and (
            '"dependencies"' in body or '"require"' in body
        ):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Dependency manifest exposed",
                    description="A public dependency manifest reveals application packages and version constraints.",
                    severity="low",
                    category="Information Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Detailed dependency metadata can help attackers prioritize version-specific research.",
                    recommendation="Exclude build manifests from public artifacts unless they are intentionally published.",
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
        elif path in {"/swagger.json", "/openapi.json", "/v3/api-docs"} and (
            '"swagger"' in body or '"openapi"' in body or '"paths"' in body and '"info"' in body
        ):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="API specification exposed",
                    description="A machine-readable API specification is publicly reachable.",
                    severity="low",
                    category="Information Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Unintended API documentation can reveal internal operations and sensitive endpoint names.",
                    recommendation="Confirm the specification is intended to be public; otherwise restrict it to authenticated users.",
                ),
            )
        elif path == "/actuator/env" and ("propertysources" in body or "activeprofiles" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Application environment endpoint exposed",
                    description="A Spring Boot environment endpoint appears publicly reachable.",
                    severity="high",
                    category="Diagnostic Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Environment endpoints can reveal configuration values, service addresses, and secret names.",
                    recommendation="Disable public actuator access and require authenticated administrative networking.",
                ),
            )
        elif path == "/actuator/heapdump" and (
            "octet-stream" in content_type or "application/gzip" in content_type
        ):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Heap dump endpoint exposed",
                    description="A downloadable application heap dump appears publicly reachable.",
                    severity="critical",
                    category="Diagnostic Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path, "content_type": content_type},
                    business_impact="Heap dumps can contain credentials, session tokens, customer data, and encryption material.",
                    recommendation="Disable the endpoint publicly, rotate potentially exposed secrets, and investigate downloads.",
                ),
            )
        elif path == "/metrics" and ("# help" in body or "# type" in body or "process_" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Metrics endpoint exposed",
                    description="An operational metrics endpoint appears publicly reachable.",
                    severity="medium",
                    category="Diagnostic Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Metrics can reveal topology, software behavior, resource use, and internal service names.",
                    recommendation="Restrict metrics to authenticated monitoring networks.",
                ),
            )
        elif path == "/debug/pprof/" and ("profiles" in body or "goroutine" in body or "heap" in body):
            _append_unique(
                findings,
                seen,
                WebExposureFinding(
                    title="Runtime profiling endpoint exposed",
                    description="A Go pprof diagnostics endpoint appears publicly reachable.",
                    severity="high",
                    category="Diagnostic Exposure",
                    evidence={"url": result.url, "status_code": result.status_code, "path": result.path},
                    business_impact="Profiling data can disclose runtime internals and may enable resource-exhaustion attacks.",
                    recommendation="Disable public profiling and restrict diagnostics to authenticated administration networks.",
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


def _looks_like_sensitive_config(body: str) -> bool:
    indicators = (
        "db_password",
        "database_password",
        "password=",
        "secret_key",
        "connectionstring",
        "define('db_",
        'define("db_',
    )
    return any(indicator in body for indicator in indicators)


def _looks_like_environment_file(body: str) -> bool:
    assignments = re.findall(r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*[^\r\n]+$", body)
    sensitive_names = re.search(
        r"(?im)^\s*(?:secret|secret_key|api_key|token|password|db_password|database_url|aws_access_key_id)\s*=",
        body,
    )
    return bool(sensitive_names or len(assignments) >= 2)


def _append_unique(findings: list[WebExposureFinding], seen: set[tuple[str, str]], finding: WebExposureFinding) -> None:
    key = (finding.title, str(finding.evidence.get("url", "")))
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)
