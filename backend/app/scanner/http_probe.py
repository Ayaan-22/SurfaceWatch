import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx


HTTP_PORT_SCHEMES = {
    80: "http",
    81: "http",
    443: "https",
    2375: "http",
    2376: "https",
    3000: "http",
    3128: "http",
    4443: "https",
    5000: "http",
    5601: "http",
    5984: "http",
    6443: "https",
    7001: "http",
    7002: "https",
    8000: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8500: "http",
    8888: "http",
    9000: "http",
    9090: "http",
    9200: "http",
    9443: "https",
    10000: "https",
    10250: "https",
    10255: "http",
    15672: "http",
}


@dataclass(frozen=True)
class HttpProbeResult:
    url: str
    status_code: int | None
    headers: dict[str, str]
    body_preview: str
    error: str | None = None
    requested_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    response_time_ms: int | None = None
    content_length: int | None = None
    tls_verified: bool | None = None


def http_targets(hostname: str, open_ports: list[int] | None = None) -> list[str]:
    """Build deterministic HTTP targets, including confirmed alternate web ports."""
    targets = [f"https://{hostname}", f"http://{hostname}"]
    for port in open_ports or []:
        scheme = HTTP_PORT_SCHEMES.get(port)
        if scheme is None or port in {80, 443}:
            continue
        targets.append(f"{scheme}://{hostname}:{port}")
    return list(dict.fromkeys(targets))


def _redirect_is_in_scope(url: str, hostname: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme in {"http", "https"} and (parsed.hostname or "").lower().rstrip(".") == hostname.lower().rstrip(".")


def _pinned_connection_url(url: str, connect_ip: str | None) -> tuple[str, str | None]:
    """Return an IP-pinned transport URL and the original Host header."""
    if not connect_ip:
        return url, None
    parsed = urlsplit(url)
    ip_literal = f"[{connect_ip}]" if ":" in connect_ip else connect_ip
    netloc = f"{ip_literal}:{parsed.port}" if parsed.port is not None else ip_literal
    default_port = 443 if parsed.scheme == "https" else 80
    host_header = parsed.hostname or ""
    if parsed.port is not None and parsed.port != default_port:
        host_header = f"{host_header}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)), host_header


def _read_response_preview(response: httpx.Response, max_body_bytes: int) -> tuple[str, int]:
    body = bytearray()
    for chunk in response.iter_bytes():
        remaining = max_body_bytes - len(body)
        if remaining <= 0:
            break
        body.extend(chunk[:remaining])
        if len(body) >= max_body_bytes:
            break
    encoding = response.encoding or "utf-8"
    return bytes(body).decode(encoding, errors="replace"), len(body)


def probe_url(
    requested_url: str,
    hostname: str,
    timeout: float,
    max_body_bytes: int,
    max_redirects: int,
    connect_ip: str | None = None,
    verify_tls: bool = True,
) -> HttpProbeResult:
    started = time.monotonic()
    current_url = requested_url
    redirects: list[str] = []
    headers = {"User-Agent": "SurfaceWatch/1.0 (+authorized-attack-surface-monitor)"}
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, headers=headers, verify=verify_tls) as client:
            for _ in range(max_redirects + 1):
                connection_url, host_header = _pinned_connection_url(current_url, connect_ip)
                request_headers = {"Host": host_header} if host_header else None
                extensions = {"sni_hostname": hostname} if connect_ip and urlsplit(current_url).scheme == "https" else None
                with client.stream("GET", connection_url, headers=request_headers, extensions=extensions) as response:
                    location = response.headers.get("location")
                    if response.is_redirect and location:
                        next_url = urljoin(current_url, location)
                        redirects.append(next_url)
                        if not _redirect_is_in_scope(next_url, hostname):
                            return HttpProbeResult(
                                url=current_url,
                                requested_url=requested_url,
                                status_code=response.status_code,
                                headers=dict(response.headers),
                                body_preview="",
                                redirect_chain=redirects,
                                response_time_ms=round((time.monotonic() - started) * 1000),
                                content_length=0,
                                tls_verified=verify_tls if urlsplit(current_url).scheme == "https" else None,
                                error="Cross-host redirect was recorded but not followed outside the authorized hostname.",
                            )
                        current_url = next_url
                        continue

                    body_preview, bytes_read = _read_response_preview(response, max_body_bytes)
                    return HttpProbeResult(
                        url=current_url,
                        requested_url=requested_url,
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body_preview=body_preview,
                        redirect_chain=redirects,
                        response_time_ms=round((time.monotonic() - started) * 1000),
                        content_length=bytes_read,
                        tls_verified=verify_tls if urlsplit(current_url).scheme == "https" else None,
                    )

            return HttpProbeResult(
                url=current_url,
                requested_url=requested_url,
                status_code=None,
                headers={},
                body_preview="",
                redirect_chain=redirects,
                response_time_ms=round((time.monotonic() - started) * 1000),
                error=f"Redirect limit of {max_redirects} exceeded.",
            )
    except httpx.HTTPError as exc:
        return HttpProbeResult(
            url=current_url,
            requested_url=requested_url,
            status_code=None,
            headers={},
            body_preview="",
            redirect_chain=redirects,
            response_time_ms=round((time.monotonic() - started) * 1000),
            error=str(exc),
        )


def probe_url_resilient(
    requested_url: str,
    hostname: str,
    timeout: float,
    max_body_bytes: int,
    max_redirects: int,
    connect_ip: str | None = None,
) -> HttpProbeResult:
    """Collect content from invalid-TLS endpoints while retaining the trust failure."""
    primary = probe_url(
        requested_url,
        hostname,
        timeout,
        max_body_bytes,
        max_redirects,
        connect_ip,
        True,
    )
    error_text = (primary.error or "").lower()
    if (
        urlsplit(requested_url).scheme != "https"
        or primary.status_code is not None
        or not any(marker in error_text for marker in ("certificate verify failed", "certificate_verify_failed", "ssl: certificate"))
    ):
        return primary

    fallback = probe_url(
        requested_url,
        hostname,
        timeout,
        max_body_bytes,
        max_redirects,
        connect_ip,
        False,
    )
    if fallback.status_code is not None:
        return HttpProbeResult(
            **{
                **fallback.__dict__,
                "error": f"TLS verification failed; response collected with verification disabled: {primary.error}",
                "tls_verified": False,
            }
        )
    return primary


def probe_http(
    hostname: str,
    timeout: float = 3.0,
    open_ports: list[int] | None = None,
    concurrency: int = 4,
    max_body_bytes: int = 65536,
    max_redirects: int = 5,
    connect_ip: str | None = None,
) -> list[HttpProbeResult]:
    targets = http_targets(hostname, open_ports)
    max_workers = max(1, min(concurrency, len(targets)))
    by_target: dict[str, HttpProbeResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="http-probe") as pool:
        future_to_target = {
            pool.submit(probe_url_resilient, target, hostname, timeout, max_body_bytes, max_redirects, connect_ip): target
            for target in targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                by_target[target] = future.result()
            except Exception as exc:  # Defensive: preserve every planned endpoint.
                by_target[target] = HttpProbeResult(
                    url=target,
                    requested_url=target,
                    status_code=None,
                    headers={},
                    body_preview="",
                    error=str(exc),
                )
    return [by_target[target] for target in targets]
