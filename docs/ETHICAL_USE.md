# Ethical Use

SurfaceWatch must only be used for domains and IP addresses owned by the user or covered by explicit authorization.

Do not use SurfaceWatch for:

- Unauthorized scanning.
- Exploitation.
- Credential attacks.
- Brute force discovery.
- Destructive testing.
- Attempts to bypass access controls.

Default scanner behavior is intentionally conservative: passive-first discovery, limited TCP ports, short timeouts, low concurrency, and evidence-based reporting.

Aggressive scanner behavior must be explicitly selected and should be used only when authorization covers deeper active assessment of the selected domain scope. Aggressive mode expands TCP service coverage and performs safe HTTP GET probes for common public exposure mistakes, but it still avoids exploitation, brute force, credential testing, destructive payloads, and bypass attempts.
