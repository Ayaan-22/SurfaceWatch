import socket
from dataclasses import dataclass


SERVICE_GUESSES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker-api",
    2376: "docker-api-tls",
    3000: "node-dev",
    5000: "flask-dev",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9000: "admin-http",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
}


@dataclass(frozen=True)
class PortCheckResult:
    port: int
    protocol: str
    status: str
    service_guess: str | None
    banner: str | None = None


def check_tcp_port(hostname: str, port: int, timeout: float = 1.5) -> PortCheckResult:
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(0.5)
            banner = None
            if port in {21, 22, 23, 25, 110, 143}:
                try:
                    banner = sock.recv(120).decode("utf-8", errors="ignore").strip()
                except OSError:
                    banner = None
            return PortCheckResult(port=port, protocol="tcp", status="open", service_guess=SERVICE_GUESSES.get(port), banner=banner)
    except socket.timeout:
        return PortCheckResult(port=port, protocol="tcp", status="filtered", service_guess=SERVICE_GUESSES.get(port))
    except OSError:
        return PortCheckResult(port=port, protocol="tcp", status="closed", service_guess=SERVICE_GUESSES.get(port))
