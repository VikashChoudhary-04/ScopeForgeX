import os

# ✅ Tool-specific preferred defaults
DEFAULT_SUBDOMAIN_WORDLIST = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
DEFAULT_WEB_FUZZ_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt"


def _exists(p: str) -> bool:
    return os.path.exists(p) and os.path.isfile(p)


def find_default_subdomain_wordlist() -> str | None:
    """
    Default for Subhunt / Subdomain bruteforce
    """
    candidates = [
        DEFAULT_SUBDOMAIN_WORDLIST,
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    ]
    for p in candidates:
        if _exists(p):
            return p
    return None


def find_default_web_fuzz_wordlist() -> str | None:
    """
    Default for FFUF / directory fuzzing
    """
    candidates = [
        DEFAULT_WEB_FUZZ_WORDLIST,
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    ]
    for p in candidates:
        if _exists(p):
            return p
    return None


def is_valid_wordlist(path: str) -> bool:
    return _exists(path)
