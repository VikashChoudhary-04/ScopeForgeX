"""
ScopeForgeX Target Merger
=========================

Utilities for reading, validating, deduplicating, and merging
pipeline target files.

v0.4.0
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.validators import looks_like_hostname


def read_lines(path: str) -> list[str]:
    """
    Read a target file, returning only valid hostnames/IPs.

    Invalid lines, blank lines, banners, and other noise are
    automatically discarded.
    """

    file = Path(path)

    if not file.exists():
        return []

    cleaned: list[str] = []

    with file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as infile:

        for line in infile:
            value = line.strip()

            if not value:
                continue

            if looks_like_hostname(value):
                cleaned.append(value.lower())

    return cleaned


def merge_targets(
    output_path: str,
    *input_paths: str,
) -> int:
    """
    Merge multiple target files into a single deduplicated output.

    Returns:
        Number of unique targets written.
    """

    merged: list[str] = []
    seen: set[str] = set()

    for path in input_paths:
        for target in read_lines(path):

            if target in seen:
                continue

            seen.add(target)
            merged.append(target)

    outfile = Path(output_path)

    if outfile.parent != Path():
        outfile.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    with outfile.open(
        "w",
        encoding="utf-8",
    ) as out:

        if merged:
            out.write("\n".join(merged))
            out.write("\n")

    return len(merged)
