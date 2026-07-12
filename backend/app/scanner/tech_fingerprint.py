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
    cookies = normalized_headers.get("set-cookie", "")
    combined_headers = " ".join(f"{key}:{value}" for key, value in normalized_headers.items())

    checks = [
        ("Nginx", "Web Server", "nginx", server, 85),
        ("Apache", "Web Server", "apache", server, 85),
        ("Microsoft IIS", "Web Server", "microsoft-iis", server, 90),
        ("Caddy", "Web Server", "caddy", server, 90),
        ("Envoy", "Proxy", "envoy", server + combined_headers, 85),
        ("Gunicorn", "Application Server", "gunicorn", server, 90),
        ("uvicorn", "Application Server", "uvicorn", server, 90),
        ("Cloudflare", "CDN/WAF", "cloudflare", server + normalized_headers.get("cf-ray", ""), 90),
        ("Akamai", "CDN/WAF", "akamai", combined_headers, 85),
        ("Fastly", "CDN", "fastly", combined_headers, 85),
        ("Vercel", "Hosting Platform", "x-vercel-", combined_headers, 95),
        ("Netlify", "Hosting Platform", "x-nf-request-id", combined_headers, 95),
        ("AWS Application Load Balancer", "Cloud Infrastructure", "awselb", cookies, 85),
        ("Microsoft Azure App Service", "Cloud Platform", "arraffinity", cookies, 90),
        ("Heroku", "Cloud Platform", "heroku", combined_headers, 80),
        ("Express", "Backend Framework", "express", powered_by, 85),
        ("PHP", "Runtime", "php", powered_by, 80),
        ("ASP.NET", "Backend Framework", "asp.net", powered_by, 85),
        ("Django", "Backend Framework", "csrftoken", cookies, 75),
        ("Laravel", "Backend Framework", "laravel_session", cookies, 90),
        ("Ruby on Rails", "Backend Framework", "_session", cookies + powered_by, 60),
        ("Next.js", "Frontend Framework", "_next/", body, 85),
        ("Nuxt", "Frontend Framework", "_nuxt/", body, 85),
        ("SvelteKit", "Frontend Framework", "__sveltekit", body, 85),
        ("React", "Frontend Framework", "react", body, 60),
        ("Vue", "Frontend Framework", "vue", body, 60),
        ("Angular", "Frontend Framework", "ng-version", body, 75),
        ("WordPress", "CMS", "wp-content", body, 90),
        ("Drupal", "CMS", "drupal-settings-json", body, 90),
        ("Joomla", "CMS", "com_content", body, 75),
        ("Ghost", "CMS", "ghost/api", body, 85),
        ("Magento", "Commerce", "mage/cookies", body, 85),
        ("Shopify", "Commerce", "cdn.shopify.com", body, 90),
        ("Grafana", "Monitoring", "grafana", body, 80),
        ("Kibana", "Monitoring", "kbn-name", combined_headers, 90),
        ("jQuery", "JavaScript Library", "jquery", body, 70),
        ("Bootstrap", "CSS Framework", "bootstrap", body, 70),
    ]
    seen: set[str] = set()
    for name, category, needle, haystack, confidence in checks:
        if needle in haystack:
            if name in seen:
                continue
            seen.add(name)
            signals.append(TechnologySignal(name, category, confidence, f"Matched '{needle}' in public response"))
    return signals
