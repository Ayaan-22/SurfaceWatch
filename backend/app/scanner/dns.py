import socket


def resolve_host(hostname: str) -> list[str]:
    try:
        return sorted({result[-1][0] for result in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []
