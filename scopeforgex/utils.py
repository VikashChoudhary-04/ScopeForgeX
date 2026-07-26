"""
ScopeForgeX Utility Functions
=============================

Shared helper functions used throughout the framework.

v0.4.0
"""

from __future__ import annotations

import os
from datetime import datetime

import yaml


def load_yaml(path: str) -> dict:
    """
    Load a YAML file.

    Returns an empty dictionary if the YAML document is empty.
    """

    with open(path, "r", encoding="utf-8") as infile:
        return yaml.safe_load(infile) or {}


def ensure_dir(path: str):
    """
    Create a directory if it does not already exist.
    """

    os.makedirs(path, exist_ok=True)


def timestamp() -> str:
    """
    Return a filesystem-safe timestamp.
    """

    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def read_file_safe(
    path: str,
    max_bytes: int = 200_000,
) -> str:
    """
    Read a text file safely.

    The read size is intentionally limited because this function is
    primarily used for log analysis.

    Returns:
        File contents, or an empty string if unavailable.
    """

    if not os.path.exists(path):
        return ""

    try:
        with open(path, "rb") as infile:
            data = infile.read(max_bytes)

        return data.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:
        return ""


def analyze_common_blocks(log_text: str) -> list[str]:
    """
    Detect common blocking, networking and infrastructure issues.
    """

    text = (log_text or "").lower()

    issues: list[str] = []

    checks = (
        (
            (" 403", "forbidden"),
            "403 Forbidden detected (likely WAF/blocking).",
        ),
        (
            (" 401", "unauthorized"),
            "401 Unauthorized detected (authentication required).",
        ),
        (
            (" 429", "too many requests"),
            "429 Too Many Requests detected (rate limiting).",
        ),
        (
            ("access denied",),
            "Access denied detected (blocked by server/WAF).",
        ),
        (
            ("cloudflare", "captcha"),
            "Cloudflare protection detected (captcha/WAF).",
        ),
        (
            ("cloudflare", "attention required"),
            "Cloudflare protection detected (captcha/WAF).",
        ),
        (
            ("waf", "detected"),
            "WAF blocking detected.",
        ),
        (
            ("waf", "blocked"),
            "WAF blocking detected.",
        ),
        (
            ("ssl", "error"),
            "SSL/TLS error detected (certificate/handshake issue).",
        ),
        (
            ("ssl", "handshake"),
            "SSL/TLS error detected (certificate/handshake issue).",
        ),
        (
            ("ssl", "certificate"),
            "SSL/TLS error detected (certificate/handshake issue).",
        ),
        (
            ("connection refused",),
            "Connection refused (target not accepting connections).",
        ),
        (
            ("timeout",),
            "Timeout detected (slow target/network filtering).",
        ),
        (
            ("timed out",),
            "Timeout detected (slow target/network filtering).",
        ),
        (
            ("no route to host",),
            "No route to host (network unreachable).",
        ),
        (
            (
                "name or service not known",
                "temporary failure in name resolution",
            ),
            "DNS resolution failure detected.",
        ),
        (
            ("indexerror", "sublist3r"),
            "Sublist3r crashed (source blocking/page change).",
        ),
    )

    for keywords, message in checks:
        if all(keyword in text for keyword in keywords):
            issues.append(message)

    return issues


def build_notes_from_log(
    log_path: str,
    base_note: str = "",
) -> str:
    """
    Generate a concise status message based on a log file.
    """

    issues = analyze_common_blocks(
        read_file_safe(log_path)
    )

    if not issues:
        return base_note.strip() if base_note else "Completed."

    prefix = (
        base_note.strip()
        if base_note
        else "Completed with warnings."
    )

    return (
        prefix
        + " | "
        + " ".join(f"[{issue}]" for issue in issues)
    )
