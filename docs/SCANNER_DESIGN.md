# Scanner Design

SurfaceWatch uses authorization-focused scanning with two profiles: conservative default monitoring and explicit aggressive assessment.

## Principles

- Multi-source passive discovery for both profiles, with bounded common-name DNS enrichment only in explicitly authorized aggressive mode.
- Strict default port list for safe monitoring.
- Expanded service coverage for explicit aggressive scans.
- Short network timeouts and bounded scan duration.
- Bounded target, port, HTTP, and exposure-probe concurrency.
- No exploitation, brute force, credential testing, destructive payloads, or bypass attempts.
- One host failure must not fail the whole scan.
- Every planned target receives an immutable manifest, including negative, blocked, skipped, failed, and partial outcomes.
- Provider failures, caps, timeouts, and module errors reduce the reported coverage instead of silently dropping data.
- Atomic per-project claims, worker ownership tokens, attempts, and heartbeats prevent duplicate execution and make stale-worker recovery observable.

## Scan Profiles

- `safe`: passive seed discovery, HTTP/HTTPS probing, TLS checks, security header analysis, technology fingerprinting, and a limited public-service port list.
- `aggressive`: all safe checks, higher asset discovery ceiling, bounded common subdomain DNS enrichment, broader TCP service coverage, alternate web-port probing, and safe HTTP GET probes for common secret, backup, VCS, API-documentation, metrics, profiling, and diagnostic exposures.

## Modules

- `subdomains.py`: parallel CT/public-source discovery, source-health telemetry, live-host prioritization, cap reporting, and aggressive DNS candidates.
- `dns.py`: DNS resolution helpers.
- `http_probe.py`: root and confirmed alternate-port reachability, bounded response previews, latency/redirect metadata, and same-host redirect enforcement.
- `ssl_checker.py`: certificate metadata, invalid-chain recovery, expiry/self-signed/hostname classification, negotiated TLS version, and cipher details.
- `headers.py`: canonical missing/weak header rules, CSP/HSTS validation, CORS, cookie flags, and information-exposure checks.
- `ports.py`: concurrent bounded TCP connect checks and safe banner reads for server-first text services.
- `web_exposure.py`: concurrent aggressive-mode checks for common secret, backup, source-control, manifest, API documentation, and diagnostic exposures.
- `tech_fingerprint.py`: evidence-based technology signals.
- `risk_engine.py`: score normalization and risk levels.
- `change_detector.py`: change classification.
- `report_builder.py`: immutable scan-scoped PDF/Excel output with all findings and coverage warnings.
- `scheduler.py`: atomic due-job dispatch and autonomous scheduler loop.

## Completeness Contract

A scan is `completed` only when discovery sources did not fail, the discovery result was not capped, all target manifests reached a terminal outcome, and no scanner module failed. Otherwise the scan is `partial`, with `partial_reason`, source metadata, target errors, and check coverage retained. Canonical asset/finding lifecycle rows may move forward over time; historical reports and scan detail views read the immutable `scan_asset_results` manifest instead.
