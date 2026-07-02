import socket
from dataclasses import dataclass


SERVICE_GUESSES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    443: "https",
    3000: "node-dev",
    5000: "flask-dev",
    5432: "postgresql",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
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
            if port in {21, 22, 25}:
                try:
                    banner = sock.recv(120).decode("utf-8", errors="ignore").strip()
                except OSError:
                    banner = None
            return PortCheckResult(port=port, protocol="tcp", status="open", service_guess=SERVICE_GUESSES.get(port), banner=banner)
    except socket.timeout:
        return PortCheckResult(port=port, protocol="tcp", status="filtered", service_guess=SERVICE_GUESSES.get(port))
    except OSError:
        return PortCheckResult(port=port, protocol="tcp", status="closed", service_guess=SERVICE_GUESSES.get(port))
