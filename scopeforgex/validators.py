"""
ScopeForgeX Validators
======================

Shared validation helpers for domains, IP addresses, CIDRs,
host:port combinations, and URL/hostname detection.

v0.4.0
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)

# Matches hostname:port or IPv4:port.
# IPv6 literals are handled separately by urlparse/ipaddress.
_HOST_PORT_RE = re.compile(
    r"^(?P<host>[^:]+):(?P<port>\d{1,5})$"
)

_BANNER_CHARS = ("│", "┌", "└", "─")


def is_valid_domain(domain: str) -> bool:
    """
    Validate a DNS hostname.

    Examples:
        example.com
        api.example.com
    """

    domain = (domain or "").strip().rstrip(".")

    return bool(_DOMAIN_RE.fullmatch(domain))


def is_valid_ip_or_cidr(value: str) -> bool:
    """
    Validate an IPv4/IPv6 address or CIDR block.
    """

    value = (value or "").strip()

    if not value:
        return False

    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_ip(value: str) -> bool:
    """
    Validate a single IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split_host_port(value: str):
    """
    Split a host[:port] string.

    Returns:
        (host, port) if a valid port exists.
        (value, None) otherwise.
    """

    match = _HOST_PORT_RE.fullmatch(value)

    if not match:
        return value, None

    host = match.group("host")
    port = int(match.group("port"))

    if not (1 <= port <= 65535):
        return value, None

    return host, port


def _contains_banner_chars(text: str) -> bool:
    """
    Detect common terminal/table drawing characters.
    """

    return any(ch in text for ch in _BANNER_CHARS)


def looks_like_hostname(line: str) -> bool:
    """
    Determine whether a line is likely to contain a hostname, IP,
    URL, or host:port combination.

    Accepted examples:

        example.com
        api.example.com
        192.168.1.10
        192.168.1.10:8080
        http://example.com
        https://example.com
        http://192.168.1.10:3000
        https://example.com/login

    Rejected examples:

        ASCII banners
        Unicode tables
        Random sentences
    """

    value = (line or "").strip()

    if not value:
        return False

    if _contains_banner_chars(value):
        return False

    if " " in value:
        return False

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)

        host = parsed.hostname

        if not host:
            return False

        return (
            _is_valid_ip(host)
            or is_valid_domain(host)
        )

    host, _ = _split_host_port(value)

    return (
        _is_valid_ip(host)
        or is_valid_domain(host)
    )
