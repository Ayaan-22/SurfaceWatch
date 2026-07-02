from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class HttpProbeResult:
    url: str
    status_code: int | None
    headers: dict[str, str]
    body_preview: str
    error: str | None = None


def probe_http(hostname: str, timeout: float = 3.0) -> list[HttpProbeResult]:
    results: list[HttpProbeResult] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = httpx.get(url, follow_redirects=True, timeout=timeout)
            results.append(
                HttpProbeResult(
                    url=str(response.url),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body_preview=response.text[:5000],
                )
            )
        except httpx.HTTPError as exc:
            results.append(HttpProbeResult(url=url, status_code=None, headers={}, body_preview="", error=str(exc)))
    return results
