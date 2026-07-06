# Scanner Design

SurfaceWatch uses authorization-focused scanning with two profiles: conservative default monitoring and explicit aggressive assessment.

## Principles

- Passive-first discovery for both profiles.
- Strict default port list for safe monitoring.
- Expanded service coverage for explicit aggressive scans.
- Short network timeouts and bounded scan duration.
- Low to moderate concurrency.
- No exploitation, brute force, credential testing, destructive payloads, or bypass attempts.
- One host failure must not fail the whole scan.

## Scan Profiles

- `safe`: passive seed discovery, HTTP/HTTPS probing, TLS checks, security header analysis, technology fingerprinting, and a limited public-service port list.
- `aggressive`: all safe checks, higher asset discovery ceiling, broader TCP service coverage, and safe HTTP GET probes for common exposure paths such as `.env`, `.git/config`, backup archives, database dumps, directory listings, diagnostic pages, and server-status endpoints.

## Modules

- `subdomains.py`: passive seed discovery and later CT/public-source enrichment.
- `dns.py`: DNS resolution helpers.
- `http_probe.py`: HTTP/HTTPS reachability and safe response collection.
- `ssl_checker.py`: certificate issuer, names, validity, expiry, and status.
- `headers.py`: security header presence and recommendation analysis.
- `ports.py`: limited TCP connect checks and safe banner reads for a few text services.
- `web_exposure.py`: explicit aggressive-mode checks for common web exposure mistakes.
- `tech_fingerprint.py`: evidence-based technology signals.
- `risk_engine.py`: score normalization and risk levels.
- `change_detector.py`: change classification.
- `report_builder.py`: report constants and later PDF/Excel builders.
- `scheduler.py`: scan cadence helpers.
