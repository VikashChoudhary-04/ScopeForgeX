import re


def is_valid_domain(domain: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain.strip()))


def is_valid_ip_or_cidr(value: str) -> bool:
    return len(value.strip()) > 0


def looks_like_hostname(line: str) -> bool:
    """
    Strict hostname/subdomain validator for cleaning tool outputs.
    Accepts: sub.domain.tld
    Rejects: banners, unicode boxes, random text
    """
    s = (line or "").strip().lower()

    if not s:
        return False

    # Must not contain spaces or box characters
    if " " in s or "│" in s or "┌" in s or "└" in s or "─" in s:
        return False

    # Remove scheme if mistakenly included
    s = s.replace("http://", "").replace("https://", "")
    s = s.split("/")[0]

    # Basic hostname pattern
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", s):
        return False

    # Avoid weird cases
    if s.startswith(".") or s.endswith("."):
        return False

    return True
