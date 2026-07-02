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
