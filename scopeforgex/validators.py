import re

def is_valid_domain(domain: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain.strip()))

def is_valid_ip_or_cidr(value: str) -> bool:
    return len(value.strip()) > 0
