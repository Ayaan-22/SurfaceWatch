from dataclasses import dataclass
from html.parser import HTMLParser

import httpx

from app.scanner.dns import resolve_host


PASSIVE_PREFIXES = ("www", "mail", "api", "app", "portal")
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


def _seed_hostnames(domain: str) -> set[str]:
    normalized = domain.strip().lower().rstrip(".")
    return {normalized, *(f"{prefix}.{normalized}" for prefix in PASSIVE_PREFIXES)}


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
    try:
        response = httpx.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=timeout_seconds,
            follow_redirects=True,
        )
        response.raise_for_status()
        return _extract_crtsh_hostnames(domain, response.json())
    except (httpx.HTTPError, ValueError):
        return set()


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
    try:
        response = httpx.get(
            CERTSPOTTER_URL,
            params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        return _extract_certspotter_hostnames(domain, response.json())
    except (httpx.HTTPError, ValueError):
        return set()


def _extract_hackertarget_hostnames(domain: str, text: str) -> set[str]:
    hostnames: set[str] = set()
    for line in text.splitlines():
        raw_hostname = line.split(",", 1)[0]
        hostname = _normalize_discovered_hostname(raw_hostname, domain)
        if hostname:
            hostnames.add(hostname)
    return hostnames


def _hackertarget_hostnames(domain: str, timeout_seconds: float) -> set[str]:
    try:
        response = httpx.get(HACKERTARGET_HOSTSEARCH_URL, params={"q": domain}, timeout=timeout_seconds)
        response.raise_for_status()
        return _extract_hackertarget_hostnames(domain, response.text)
    except httpx.HTTPError:
        return set()


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
    try:
        response = httpx.get(
            RAPIDDNS_URL.format(domain=domain),
            params={"full": "1"},
            timeout=timeout_seconds,
            follow_redirects=True,
        )
        response.raise_for_status()
        return _extract_rapiddns_hostnames(domain, response.text)
    except httpx.HTTPError:
        return set()


def _ordered_hostnames(hostnames: set[str], domain: str, max_candidates: int) -> list[str]:
    ordered = sorted(hostnames - {domain})
    return [domain, *ordered][:max_candidates]


def passive_seed_discovery(domain: str, timeout_seconds: float = 5.0, max_candidates: int = 250) -> list[SubdomainCandidate]:
    normalized_domain = domain.strip().lower().rstrip(".")
    seed_hostnames = _seed_hostnames(normalized_domain)
    crtsh_hostnames = _certificate_transparency_hostnames(normalized_domain, timeout_seconds)
    certspotter_hostnames = _certspotter_hostnames(normalized_domain, timeout_seconds)
    hackertarget_hostnames = _hackertarget_hostnames(normalized_domain, timeout_seconds)
    rapiddns_hostnames = _rapiddns_hostnames(normalized_domain, timeout_seconds)
    certificate_hostnames = crtsh_hostnames | certspotter_hostnames
    external_hostnames = certificate_hostnames | hackertarget_hostnames | rapiddns_hostnames
    candidates = _ordered_hostnames(seed_hostnames | external_hostnames, normalized_domain, max_candidates)
    discovered: list[SubdomainCandidate] = []
    for hostname in candidates:
        ips = resolve_host(hostname)
        if hostname in certificate_hostnames:
            source = "certificate_transparency"
        elif hostname in hackertarget_hostnames:
            source = "hostsearch"
        elif hostname in rapiddns_hostnames:
            source = "rapiddns"
        else:
            source = "passive_seed_dns"
        discovered.append(
            SubdomainCandidate(
                hostname=hostname,
                ip_addresses=ips,
                source=source,
                status="active" if ips else "unknown",
            )
        )
    return discovered
