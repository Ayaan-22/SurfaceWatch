import ipaddress
import re
from dataclasses import dataclass


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


@dataclass(frozen=True)
class DomainValidationResult:
    normalized: str
    is_valid: bool
    reason: str | None = None


def normalize_domain(value: str) -> str:
    candidate = value.strip().lower()
    candidate = candidate.removeprefix("http://").removeprefix("https://").split("/")[0]
    candidate = candidate.split(":")[0]
    return candidate.rstrip(".")


def validate_public_domain(value: str, allow_internal_targets: bool = False) -> DomainValidationResult:
    candidate = normalize_domain(value)
    if not candidate:
        return DomainValidationResult(candidate, False, "Domain is required.")

    try:
        ip = ipaddress.ip_address(candidate)
        if allow_internal_targets:
            return DomainValidationResult(candidate, True)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return DomainValidationResult(candidate, False, "Internal, loopback, reserved, and private IPs are blocked.")
        return DomainValidationResult(candidate, True)
    except ValueError:
        pass

    if candidate in {"localhost", "localdomain"} or candidate.endswith(".local"):
        return DomainValidationResult(candidate, False, "Localhost and internal-only domains are blocked.")
    if not DOMAIN_RE.match(candidate):
        return DomainValidationResult(candidate, False, "Enter a valid public domain such as example.com.")
    return DomainValidationResult(candidate, True)
