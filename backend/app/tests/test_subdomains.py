from app.scanner import subdomains


def test_extract_crtsh_hostnames_deduplicates_wildcards_and_sans() -> None:
    rows = [
        {"name_value": "*.example.com\napi.example.com\noutside.test", "common_name": "www.example.com"},
        {"name_value": "API.EXAMPLE.COM.", "common_name": None},
    ]

    assert subdomains._extract_crtsh_hostnames("example.com", rows) == {
        "api.example.com",
        "example.com",
        "www.example.com",
    }


def test_extract_certspotter_hostnames_reads_dns_names() -> None:
    rows = [
        {"dns_names": ["*.example.com", "shop.example.com", "ignored.test"]},
        {"dns_names": ["SHOP.EXAMPLE.COM."]},
    ]

    assert subdomains._extract_certspotter_hostnames("example.com", rows) == {
        "example.com",
        "shop.example.com",
    }


def test_extract_hackertarget_hostnames_reads_csv_rows() -> None:
    text = "example.com,203.0.113.1\napi.example.com,203.0.113.2\noutside.test,203.0.113.3"

    assert subdomains._extract_hackertarget_hostnames("example.com", text) == {
        "example.com",
        "api.example.com",
    }


def test_extract_rapiddns_hostnames_reads_table_cells() -> None:
    html = """
    <table>
      <tr><td>staging.example.com</td><td>203.0.113.10</td></tr>
      <tr><td>outside.test</td><td>A</td></tr>
      <tr><td>WWW.EXAMPLE.COM.</td><td>CNAME</td></tr>
    </table>
    """

    assert subdomains._extract_rapiddns_hostnames("example.com", html) == {
        "staging.example.com",
        "www.example.com",
    }


def test_passive_discovery_includes_certificate_transparency_results(monkeypatch) -> None:
    monkeypatch.setattr(
        subdomains,
        "_certificate_transparency_hostnames",
        lambda domain, timeout_seconds: {"shop.example.com", "cdn.example.com"},
    )
    monkeypatch.setattr(subdomains, "_certspotter_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_hackertarget_hostnames", lambda domain, timeout_seconds: {"dns.example.com"})
    monkeypatch.setattr(subdomains, "_rapiddns_hostnames", lambda domain, timeout_seconds: {"rapid.example.com"})
    monkeypatch.setattr(subdomains, "resolve_host", lambda hostname: ["203.0.113.10"] if hostname == "shop.example.com" else [])

    candidates = subdomains.passive_seed_discovery("example.com", timeout_seconds=1.0, max_candidates=20)
    hostnames = {candidate.hostname for candidate in candidates}

    assert "shop.example.com" in hostnames
    assert "cdn.example.com" in hostnames
    assert "dns.example.com" in hostnames
    assert "rapid.example.com" in hostnames
    assert "api.example.com" in hostnames
    assert next(candidate for candidate in candidates if candidate.hostname == "shop.example.com").status == "active"
    assert next(candidate for candidate in candidates if candidate.hostname == "dns.example.com").source == "hostsearch"


def test_passive_discovery_respects_max_candidates_with_root_first(monkeypatch) -> None:
    monkeypatch.setattr(
        subdomains,
        "_certificate_transparency_hostnames",
        lambda domain, timeout_seconds: {f"asset-{index}.example.com" for index in range(20)},
    )
    monkeypatch.setattr(subdomains, "_certspotter_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_hackertarget_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_rapiddns_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "resolve_host", lambda hostname: [])

    candidates = subdomains.passive_seed_discovery("example.com", timeout_seconds=1.0, max_candidates=5)

    assert len(candidates) == 5
    assert candidates[0].hostname == "example.com"


def test_discovery_exposes_provider_failures_instead_of_silently_dropping_results(monkeypatch) -> None:
    monkeypatch.setattr(
        subdomains,
        "_certificate_transparency_hostnames",
        lambda domain, timeout_seconds: (_ for _ in ()).throw(RuntimeError("provider unavailable")),
    )
    monkeypatch.setattr(subdomains, "_certspotter_hostnames", lambda domain, timeout_seconds: {"shop.example.com"})
    monkeypatch.setattr(subdomains, "_hackertarget_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_rapiddns_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "resolve_host", lambda hostname: ["93.184.216.34"] if hostname == "shop.example.com" else [])

    result = subdomains.discover_subdomains("example.com", timeout_seconds=0.1, max_candidates=20)

    assert result.complete is False
    assert result.sources["crtsh"].status == "failed"
    assert "provider unavailable" in (result.sources["crtsh"].error or "")
    assert any(candidate.hostname == "shop.example.com" for candidate in result.candidates)


def test_aggressive_discovery_adds_bounded_common_dns_candidates(monkeypatch) -> None:
    monkeypatch.setattr(subdomains, "_certificate_transparency_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_certspotter_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_hackertarget_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "_rapiddns_hostnames", lambda domain, timeout_seconds: set())
    monkeypatch.setattr(subdomains, "resolve_host", lambda hostname: ["93.184.216.34"] if hostname == "admin.example.com" else [])

    result = subdomains.discover_subdomains("example.com", timeout_seconds=0.1, max_candidates=100, aggressive_dns=True)

    admin = next(candidate for candidate in result.candidates if candidate.hostname == "admin.example.com")
    assert admin.source == "aggressive_dns"
    assert admin.status == "active"
    assert result.aggressive_dns_enabled is True
