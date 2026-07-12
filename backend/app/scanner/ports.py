import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


SERVICE_GUESSES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http-alt",
    111: "rpcbind",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
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
    1883: "mqtt",
    2049: "nfs",
    2181: "zookeeper",
    2375: "docker-api",
    2376: "docker-api-tls",
    2379: "etcd-client",
    2380: "etcd-peer",
    3000: "node-dev",
    3128: "http-proxy",
    5000: "flask-dev",
    3389: "rdp",
    4443: "https-alt",
    5432: "postgresql",
    5672: "amqp",
    5601: "kibana",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes-api",
    7001: "weblogic",
    7002: "weblogic-tls",
    8000: "http-alt",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    8500: "consul-http",
    8888: "http-alt",
    9000: "admin-http",
    9090: "admin-http",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    9443: "https-alt",
    10000: "web-admin",
    10250: "kubelet-api",
    10255: "kubelet-readonly",
    11211: "memcached",
    15672: "rabbitmq-management",
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
    error: str | None = None


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
    except socket.timeout as exc:
        return PortCheckResult(
            port=port,
            protocol="tcp",
            status="filtered",
            service_guess=SERVICE_GUESSES.get(port),
            error=str(exc) or "connection timed out",
        )
    except OSError as exc:
        # Refusal is a definitive closed result. Routing and name-resolution
        # failures are retained separately instead of being mislabeled closed.
        error_code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        refused_codes = {61, 111, 10061}
        status = "closed" if isinstance(exc, ConnectionRefusedError) or error_code in refused_codes else "unreachable"
        return PortCheckResult(
            port=port,
            protocol="tcp",
            status=status,
            service_guess=SERVICE_GUESSES.get(port),
            error=None if status == "closed" else str(exc),
        )


def check_tcp_ports(
    hostname: str,
    ports: list[int],
    timeout: float = 1.5,
    concurrency: int = 10,
) -> list[PortCheckResult]:
    """Check a bounded port set concurrently and retain one result per port."""
    ordered_ports = list(dict.fromkeys(ports))
    if not ordered_ports:
        return []

    max_workers = max(1, min(concurrency, len(ordered_ports)))
    results_by_port: dict[int, PortCheckResult] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="tcp-port") as pool:
        future_to_port = {
            pool.submit(check_tcp_port, hostname, port, timeout): port
            for port in ordered_ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results_by_port[port] = future.result()
            except Exception as exc:  # Defensive: one port must not erase the set.
                results_by_port[port] = PortCheckResult(
                    port=port,
                    protocol="tcp",
                    status="error",
                    service_guess=SERVICE_GUESSES.get(port),
                    error=str(exc),
                )

    return [results_by_port[port] for port in ordered_ports]
