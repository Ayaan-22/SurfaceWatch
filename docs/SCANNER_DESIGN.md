# Scanner Design

SurfaceWatch uses conservative, authorization-focused scanning.

## Principles

- Passive-first discovery.
- Strict default port list.
- Short network timeouts.
- Low concurrency.
- No exploitation, brute force, credential testing, destructive payloads, or bypass attempts.
- One host failure must not fail the whole scan.

## Modules

- `subdomains.py`: passive seed discovery and later CT/public-source enrichment.
- `dns.py`: DNS resolution helpers.
- `http_probe.py`: HTTP/HTTPS reachability and safe response collection.
- `ssl_checker.py`: certificate issuer, names, validity, expiry, and status.
- `headers.py`: security header presence and recommendation analysis.
- `ports.py`: limited TCP connect checks and safe banner reads for a few text services.
- `tech_fingerprint.py`: evidence-based technology signals.
- `risk_engine.py`: score normalization and risk levels.
- `change_detector.py`: change classification.
- `report_builder.py`: report constants and later PDF/Excel builders.
- `scheduler.py`: scan cadence helpers.
