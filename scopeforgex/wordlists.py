"""
ScopeForgeX Wordlist Utilities
==============================

Helpers for locating default wordlists used by reconnaissance
and enumeration tools.

v0.4.0
"""

from __future__ import annotations

import os


# ----------------------------------------------------------------------
# Preferred default wordlists
# ----------------------------------------------------------------------

DEFAULT_SUBDOMAIN_WORDLIST = (
    "/usr/share/wordlists/seclists/Discovery/DNS/"
    "subdomains-top1million-5000.txt"
)

DEFAULT_WEB_FUZZ_WORDLIST = (
    "/usr/share/seclists/Discovery/Web-Content/"
    "directory-list-2.3-small.txt"
)


# ----------------------------------------------------------------------
# Candidate search paths
# ----------------------------------------------------------------------

_SUBDOMAIN_WORDLISTS = (
    DEFAULT_SUBDOMAIN_WORDLIST,
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
)

_WEB_FUZZ_WORDLISTS = (
    DEFAULT_WEB_FUZZ_WORDLIST,
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
)


def _exists(path: str) -> bool:
    """
    Return True if the given path exists and is a regular file.
    """

    return os.path.isfile(path)


def _find_first_existing(candidates: tuple[str, ...]) -> str | None:
    """
    Return the first existing file from a sequence of candidates.
    """

    for candidate in candidates:
        if _exists(candidate):
            return candidate

    return None


def find_default_subdomain_wordlist() -> str | None:
    """
    Locate the preferred subdomain brute-force wordlist.
    """

    return _find_first_existing(_SUBDOMAIN_WORDLISTS)


def find_default_web_fuzz_wordlist() -> str | None:
    """
    Locate the preferred web content discovery wordlist.
    """

    return _find_first_existing(_WEB_FUZZ_WORDLISTS)


def is_valid_wordlist(path: str) -> bool:
    """
    Validate that a wordlist exists and is a regular file.
    """

    if not path:
        return False

    return _exists(path)
