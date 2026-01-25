import os

DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
]

def find_default_wordlist() -> str | None:
    for p in DEFAULT_WORDLIST_CANDIDATES:
        if os.path.exists(p) and os.path.isfile(p):
            return p
    return None

def is_valid_wordlist(path: str) -> bool:
    return os.path.exists(path) and os.path.isfile(path)
