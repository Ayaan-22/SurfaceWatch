import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")


def resolve_host(hostname: str, timeout: float = 3.0) -> list[str]:
    try:
        future = _DNS_POOL.submit(
            socket.getaddrinfo, hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
        results = future.result(timeout=timeout)
        return sorted({result[-1][0] for result in results})
    except FuturesTimeoutError:
        future.cancel()
        return []
    except (socket.gaierror, OSError):
        return []


def is_public_ip_address(value: str) -> bool:
    try:
        ip_address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip_address.is_global


def unsafe_ip_addresses(ip_addresses: list[str]) -> list[str]:
    return [ip_address for ip_address in ip_addresses if not is_public_ip_address(ip_address)]


def resolution_is_public(ip_addresses: list[str]) -> bool:
    return bool(ip_addresses) and not unsafe_ip_addresses(ip_addresses)
