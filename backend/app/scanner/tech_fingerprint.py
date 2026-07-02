from dataclasses import dataclass


@dataclass(frozen=True)
class TechnologySignal:
    name: str
    category: str
    confidence: int
    evidence: str


def detect_technologies(headers: dict[str, str], html: str) -> list[TechnologySignal]:
    normalized_headers = {key.lower(): value.lower() for key, value in headers.items()}
    body = html.lower()
    signals: list[TechnologySignal] = []

    server = normalized_headers.get("server", "")
    powered_by = normalized_headers.get("x-powered-by", "")

    checks = [
        ("Nginx", "Web Server", "nginx", server, 85),
        ("Apache", "Web Server", "apache", server, 85),
        ("Cloudflare", "CDN/WAF", "cloudflare", server + normalized_headers.get("cf-ray", ""), 90),
        ("Express", "Backend Framework", "express", powered_by, 85),
        ("PHP", "Runtime", "php", powered_by, 80),
        ("ASP.NET", "Backend Framework", "asp.net", powered_by, 85),
        ("Next.js", "Frontend Framework", "_next/", body, 85),
        ("React", "Frontend Framework", "react", body, 60),
        ("Vue", "Frontend Framework", "vue", body, 60),
        ("Angular", "Frontend Framework", "ng-version", body, 75),
        ("WordPress", "CMS", "wp-content", body, 90),
        ("Shopify", "Commerce", "cdn.shopify.com", body, 90),
        ("jQuery", "JavaScript Library", "jquery", body, 70),
        ("Bootstrap", "CSS Framework", "bootstrap", body, 70),
    ]
    for name, category, needle, haystack, confidence in checks:
        if needle in haystack:
            signals.append(TechnologySignal(name, category, confidence, f"Matched '{needle}' in public response"))
    return signals
