"""
ScopeForgeX Shared Stage Utilities
==================================

Shared helpers used by multiple workflow stages.

v0.4.0
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.utils import ensure_dir


# ----------------------------------------------------------------------
# Standard output directory names
# ----------------------------------------------------------------------

_STAGE_DIRECTORIES = (
    "recon",
    "enum",
    "vuln",
    "exploit",
    "post",
)


def init_output_dirs(base_dir: str, target_name: str) -> str:
    """
    Create the standard ScopeForgeX output directory structure.

    Returns:
        Absolute output directory path as a string.
    """

    outdir = Path(base_dir) / target_name

    ensure_dir(str(outdir))

    for directory in _STAGE_DIRECTORIES:
        ensure_dir(str(outdir / directory))

    return str(outdir)


def pipeline_paths(outdir: str) -> dict[str, str]:
    """
    Return the canonical pipeline file paths.

    This function is the single source of truth for files exchanged
    between workflow stages.
    """

    recon = Path(outdir) / "recon"

    return {
        "hosts_raw": str(recon / "hosts_raw.txt"),
        "hosts_alive": str(recon / "hosts_alive.txt"),
        "hosts_final": str(recon / "hosts_final.txt"),
        "urls_raw": str(recon / "urls_raw.txt"),
        "urls_final": str(recon / "urls_final.txt"),
    }
