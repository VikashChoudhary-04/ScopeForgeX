import ipaddress
import re
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)

_HOST_PORT_RE = re.compile(r"^(?P<host>[^:]+):(?P<port>\d{1,5})$")


def is_valid_domain(domain: str) -> bool:
    """
    Validate a DNS hostname/domain.
    """
    domain = (domain or "").strip().rstrip(".")
    return bool(_DOMAIN_RE.fullmatch(domain))


def is_valid_ip_or_cidr(value: str) -> bool:
    """
    Validate IPv4, IPv6 or CIDR.
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
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split_host_port(value: str):
    """
    Returns:
        (host, port) or (value, None)
    """

    m = _HOST_PORT_RE.fullmatch(value)

    if not m:
        return value, None

    host = m.group("host")
    port = int(m.group("port"))

    if not (1 <= port <= 65535):
        return value, None

    return host, port


def looks_like_hostname(line: str) -> bool:
    """
    Accepts:

        example.com
        api.example.com
        192.168.1.10
        192.168.1.10:8080
        http://example.com
        https://example.com
        http://192.168.1.10:3000

    Rejects:

        banners
        unicode tables
        random text
    """

    s = (line or "").strip()

    if not s:
        return False

    # Common banner characters
    if any(ch in s for ch in ("│", "┌", "└", "─")):
        return False

    if " " in s:
        return False

    # URL?
    if s.startswith(("http://", "https://")):
        parsed = urlparse(s)

        if not parsed.hostname:
            return False

        host = parsed.hostname

        return _is_valid_ip(host) or is_valid_domain(host)

    host, _ = _split_host_port(s)

    if _is_valid_ip(host):
        return True

    if is_valid_domain(host):
        return True

    return False
