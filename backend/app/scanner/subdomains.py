from collections.abc import Iterator
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from dataclasses import asdict, dataclass
from html.parser import HTMLParser

import httpx

from app.scanner.dns import resolve_host


PASSIVE_PREFIXES = ("www", "mail", "api", "app", "portal")
AGGRESSIVE_DNS_PREFIXES = (
    "admin",
    "auth",
    "beta",
    "billing",
    "blog",
    "cdn",
    "ci",
    "client",
    "cloud",
    "cms",
    "dashboard",
    "db",
    "demo",
    "dev",
    "developer",
    "docs",
    "download",
    "files",
    "ftp",
    "gateway",
    "git",
    "grafana",
    "help",
    "internal",
    "jenkins",
    "kibana",
    "legacy",
    "login",
    "m",
    "manage",
    "media",
    "monitor",
    "mx",
    "old",
    "origin",
    "partners",
    "prod",
    "proxy",
    "remote",
    "repo",
    "s3",
    "secure",
    "shop",
    "smtp",
    "stage",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "uat",
    "upload",
    "vpn",
    "web",
    "webmail",
    "wiki",
)
CRT_SH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
HACKERTARGET_HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/"
RAPIDDNS_URL = "https://rapiddns.io/subdomain/{domain}"


@dataclass(frozen=True)
class SubdomainCandidate:
    hostname: str
    ip_addresses: list[str]
    source: str
    status: str


@dataclass(frozen=True)
class DiscoverySourceStatus:
    status: str
    count: int
    duration_ms: int
    error: str | None = None


@dataclass(frozen=True)
class DiscoveryResult:
    candidates: list[SubdomainCandidate]
    sources: dict[str, DiscoverySourceStatus]
    total_candidates: int
    truncated: bool
    aggressive_dns_enabled: bool

    @property
    def complete(self) -> bool:
        return not self.truncated and all(source.status == "completed" for source in self.sources.values())

    def metadata(self) -> dict:
        return {
            "sources": {name: asdict(source) for name, source in self.sources.items()},
            "total_candidates": self.total_candidates,
            "returned_candidates": len(self.candidates),
            "truncated": self.truncated,
            "complete": self.complete,
            "aggressive_dns_enabled": self.aggressive_dns_enabled,
        }


class _TableCellParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_cell = False
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "td":
            self._in_cell = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "td":
            self._in_cell = False

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            value = data.strip()
            if value:
                self.values.append(value)


def _seed_hostnames(domain: str, aggressive_dns: bool = False) -> set[str]:
    normalized = domain.strip().lower().rstrip(".")
    prefixes = [*PASSIVE_PREFIXES, *(AGGRESSIVE_DNS_PREFIXES if aggressive_dns else ())]
    return {normalized, *(f"{prefix}.{normalized}" for prefix in prefixes)}


def _normalize_discovered_hostname(hostname: str, domain: str) -> str | None:
    normalized = hostname.strip().lower().rstrip(".")
    if normalized.startswith("*."):
        normalized = normalized[2:]
    if not normalized or "*" in normalized or " " in normalized:
        return None
    if normalized == domain or normalized.endswith(f".{domain}"):
        return normalized
    return None


def _extract_crtsh_hostnames(domain: str, rows: object) -> set[str]:
    if not isinstance(rows, list):
        return set()

    hostnames: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        values = [row.get("name_value"), row.get("common_name")]
        for value in values:
            if not isinstance(value, str):
                continue
            for raw_hostname in value.splitlines():
                hostname = _normalize_discovered_hostname(raw_hostname, domain)
                if hostname:
                    hostnames.add(hostname)
    return hostnames


def _certificate_transparency_hostnames(domain: str, timeout_seconds: float) -> set[str]:
    response = httpx.get(
        CRT_SH_URL,
        params={"q": f"%.{domain}", "output": "json"},
        timeout=timeout_seconds,
        follow_redirects=True,
    )
    response.raise_for_status()
    return _extract_crtsh_hostnames(domain, response.json())


def _extract_certspotter_hostnames(domain: str, rows: object) -> set[str]:
    if not isinstance(rows, list):
        return set()

    hostnames: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        dns_names = row.get("dns_names")
        if not isinstance(dns_names, list):
            continue
        for raw_hostname in dns_names:
            if not isinstance(raw_hostname, str):
                continue
            hostname = _normalize_discovered_hostname(raw_hostname, domain)
            if hostname:
                hostnames.add(hostname)
    return hostnames


def _certspotter_hostnames(domain: str, timeout_seconds: float) -> set[str]:
    response = httpx.get(
        CERTSPOTTER_URL,
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    return _extract_certspotter_hostnames(domain, response.json())


def _extract_hackertarget_hostnames(domain: str, text: str) -> set[str]:
    hostnames: set[str] = set()
    for line in text.splitlines():
        raw_hostname = line.split(",", 1)[0]
        hostname = _normalize_discovered_hostname(raw_hostname, domain)
        if hostname:
            hostnames.add(hostname)
    return hostnames


def _hackertarget_hostnames(domain: str, timeout_seconds: float) -> set[str]:
    response = httpx.get(HACKERTARGET_HOSTSEARCH_URL, params={"q": domain}, timeout=timeout_seconds)
    response.raise_for_status()
    return _extract_hackertarget_hostnames(domain, response.text)


def _extract_rapiddns_hostnames(domain: str, html: str) -> set[str]:
    parser = _TableCellParser()
    parser.feed(html)

    hostnames: set[str] = set()
    for raw_value in parser.values:
        hostname = _normalize_discovered_hostname(raw_value, domain)
        if hostname:
            hostnames.add(hostname)
    return hostnames


def _rapiddns_hostnames(domain: str, timeout_seconds: float) -> set[str]:
    response = httpx.get(
        RAPIDDNS_URL.format(domain=domain),
        params={"full": "1"},
        timeout=timeout_seconds,
        follow_redirects=True,
    )
    response.raise_for_status()
    return _extract_rapiddns_hostnames(domain, response.text)


def _ordered_hostnames(hostnames: set[str], domain: str, max_candidates: int) -> list[str]:
    ordered = sorted(hostnames - {domain}, key=lambda hostname: (hostname.count("."), hostname))
    return [domain, *ordered][:max_candidates]


def _collect_passive_sources(
    domain: str,
    timeout_seconds: float,
) -> tuple[dict[str, set[str]], dict[str, DiscoverySourceStatus]]:
    source_functions = {
        "crtsh": _certificate_transparency_hostnames,
        "certspotter": _certspotter_hostnames,
        "hostsearch": _hackertarget_hostnames,
        "rapiddns": _rapiddns_hostnames,
    }
    results: dict[str, set[str]] = {}
    statuses: dict[str, DiscoverySourceStatus] = {}
    pool = ThreadPoolExecutor(max_workers=len(source_functions), thread_name_prefix="subdomain-source")
    submitted_at: dict[str, float] = {}
    try:
        futures = {}
        for name, source in source_functions.items():
            submitted_at[name] = time.monotonic()
            futures[name] = pool.submit(source, domain, timeout_seconds)
        done, _ = wait(tuple(futures.values()), timeout=timeout_seconds + 1)
        for name, future in futures.items():
            if future not in done:
                future.cancel()
                results[name] = set()
                statuses[name] = DiscoverySourceStatus(
                    status="failed",
                    count=0,
                    duration_ms=round((time.monotonic() - submitted_at[name]) * 1000),
                    error=f"TimeoutError: source exceeded {timeout_seconds + 1:.1f}s",
                )
                continue
            try:
                hostnames = future.result()
                results[name] = hostnames
                statuses[name] = DiscoverySourceStatus(
                    status="completed",
                    count=len(hostnames),
                    duration_ms=round((time.monotonic() - submitted_at[name]) * 1000),
                )
            except Exception as exc:
                future.cancel()
                results[name] = set()
                statuses[name] = DiscoverySourceStatus(
                    status="failed",
                    count=0,
                    duration_ms=round((time.monotonic() - submitted_at[name]) * 1000),
                    error=f"{type(exc).__name__}: {str(exc)[:300]}",
                )
        return results, statuses
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _passive_source_hostnames(domain: str, timeout_seconds: float) -> tuple[set[str], set[str], set[str], set[str]]:
    """Compatibility wrapper for callers that only need source hostname sets."""
    results, _ = _collect_passive_sources(domain, timeout_seconds)
    return results["crtsh"], results["certspotter"], results["hostsearch"], results["rapiddns"]


def _resolve_candidates(hostnames: list[str], concurrency: int = 20) -> dict[str, list[str]]:
    if not hostnames:
        return {}
    resolved: dict[str, list[str]] = {}
    max_workers = max(1, min(concurrency, len(hostnames)))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="candidate-dns") as pool:
        future_to_hostname = {pool.submit(resolve_host, hostname): hostname for hostname in hostnames}
        for future in as_completed(future_to_hostname):
            hostname = future_to_hostname[future]
            try:
                resolved[hostname] = future.result()
            except Exception:
                resolved[hostname] = []
    return resolved


def discover_subdomains(
    domain: str,
    timeout_seconds: float = 5.0,
    max_candidates: int = 250,
    aggressive_dns: bool = False,
    resolution_concurrency: int = 20,
) -> DiscoveryResult:
    normalized_domain = domain.strip().lower().rstrip(".")
    seed_hostnames = _seed_hostnames(normalized_domain, aggressive_dns=aggressive_dns)
    source_results, source_statuses = _collect_passive_sources(normalized_domain, timeout_seconds)
    crtsh_hostnames = source_results["crtsh"]
    certspotter_hostnames = source_results["certspotter"]
    hackertarget_hostnames = source_results["hostsearch"]
    rapiddns_hostnames = source_results["rapiddns"]
    certificate_hostnames = crtsh_hostnames | certspotter_hostnames
    external_hostnames = certificate_hostnames | hackertarget_hostnames | rapiddns_hostnames
    all_hostnames = seed_hostnames | external_hostnames

    seed_order = [normalized_domain]
    seed_order.extend(
        f"{prefix}.{normalized_domain}"
        for prefix in [*PASSIVE_PREFIXES, *(AGGRESSIVE_DNS_PREFIXES if aggressive_dns else ())]
    )
    seed_order = list(dict.fromkeys(hostname for hostname in seed_order if hostname in all_hostnames))
    external_order = sorted(
        all_hostnames - set(seed_order),
        key=lambda hostname: (hostname.count("."), hostname),
    )

    # Resolve a larger candidate window before the final cap so stale CT names
    # do not automatically crowd out live hosts. The hard ceiling keeps DNS work bounded.
    resolution_limit = min(2000, max(max_candidates * 2, len(seed_order)))
    resolution_order = [*seed_order, *external_order][:resolution_limit]
    resolution_started = time.monotonic()
    resolved = _resolve_candidates(resolution_order, concurrency=resolution_concurrency)
    source_statuses["dns_resolution"] = DiscoverySourceStatus(
        status="completed",
        count=sum(1 for addresses in resolved.values() if addresses),
        duration_ms=round((time.monotonic() - resolution_started) * 1000),
    )

    prioritized_external = sorted(
        (hostname for hostname in resolution_order if hostname not in set(seed_order)),
        key=lambda hostname: (not bool(resolved.get(hostname)), hostname.count("."), hostname),
    )
    selected = [*seed_order, *prioritized_external][:max_candidates]
    aggressive_hostnames = {
        f"{prefix}.{normalized_domain}" for prefix in AGGRESSIVE_DNS_PREFIXES
    } if aggressive_dns else set()

    candidates: list[SubdomainCandidate] = []
    for hostname in selected:
        ips = resolved.get(hostname, [])
        if hostname in certificate_hostnames:
            source = "certificate_transparency"
        elif hostname in hackertarget_hostnames:
            source = "hostsearch"
        elif hostname in rapiddns_hostnames:
            source = "rapiddns"
        elif hostname in aggressive_hostnames:
            source = "aggressive_dns"
        else:
            source = "passive_seed_dns"
        candidates.append(
            SubdomainCandidate(
                hostname=hostname,
                ip_addresses=ips,
                source=source,
                status="active" if ips else "unknown",
            )
        )

    return DiscoveryResult(
        candidates=candidates,
        sources=source_statuses,
        total_candidates=len(all_hostnames),
        truncated=len(all_hostnames) > len(candidates),
        aggressive_dns_enabled=aggressive_dns,
    )


def iter_passive_seed_discovery(
    domain: str,
    timeout_seconds: float = 5.0,
    max_candidates: int = 250,
    aggressive_dns: bool = False,
) -> Iterator[SubdomainCandidate]:
    yield from discover_subdomains(
        domain,
        timeout_seconds,
        max_candidates,
        aggressive_dns=aggressive_dns,
    ).candidates


def passive_seed_discovery(
    domain: str,
    timeout_seconds: float = 5.0,
    max_candidates: int = 250,
    aggressive_dns: bool = False,
) -> list[SubdomainCandidate]:
    return list(iter_passive_seed_discovery(domain, timeout_seconds, max_candidates, aggressive_dns=aggressive_dns))
