from app.scanner.dns import is_public_ip_address, resolution_is_public, unsafe_ip_addresses
from app.scanner.orchestrator import ScanProfile, _UnsafeTargetResolution, _scan_asset_network


class _Settings:
    allow_internal_targets = False
    scan_timeout_seconds = 0.1


def test_public_resolution_requires_global_addresses_only() -> None:
    assert resolution_is_public(["93.184.216.34"])
    assert not resolution_is_public([])
    assert not resolution_is_public(["127.0.0.1"])
    assert not resolution_is_public(["169.254.169.254"])
    assert not resolution_is_public(["10.0.0.5", "93.184.216.34"])


def test_unsafe_ip_addresses_reports_non_global_addresses() -> None:
    assert unsafe_ip_addresses(["10.0.0.5", "93.184.216.34", "169.254.169.254"]) == [
        "10.0.0.5",
        "169.254.169.254",
    ]
    assert is_public_ip_address("93.184.216.34")
    assert not is_public_ip_address("not-an-ip")


def test_asset_network_scan_blocks_internal_resolution_before_probe(monkeypatch) -> None:
    called = {"http": False}

    def fake_probe_http(*args, **kwargs):
        called["http"] = True
        return []

    monkeypatch.setattr("app.scanner.orchestrator.resolve_host", lambda hostname: ["169.254.169.254"])
    monkeypatch.setattr("app.scanner.orchestrator.probe_http", fake_probe_http)

    profile = ScanProfile(name="safe", ports=[], max_assets=1, asset_timeout_seconds=1, exposure_paths=[])

    try:
        _scan_asset_network("metadata.example.org", _Settings(), profile)
    except _UnsafeTargetResolution:
        pass
    else:
        raise AssertionError("Expected unsafe target resolution to be blocked.")

    assert not called["http"]
