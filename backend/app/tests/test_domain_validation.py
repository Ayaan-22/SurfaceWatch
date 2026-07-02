from app.utils.domain_validation import validate_public_domain


def test_valid_public_domain_normalizes_scheme() -> None:
    result = validate_public_domain("https://Example.COM/path")
    assert result.is_valid
    assert result.normalized == "example.com"


def test_blocks_localhost() -> None:
    result = validate_public_domain("localhost")
    assert not result.is_valid


def test_blocks_private_ip_by_default() -> None:
    result = validate_public_domain("192.168.1.10")
    assert not result.is_valid
