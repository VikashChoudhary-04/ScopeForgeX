"""
ScopeForgeX Shared Stage Utilities
==================================

Shared helpers used by multiple workflow stages.

Responsibilities
----------------

- Create immutable per-assessment output directories.
- Generate unique assessment run identifiers.
- Initialize canonical workflow storage layers.
- Provide canonical pipeline file paths.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from scopeforgex.utils import ensure_dir


###############################################################################
# Standard Output Directory Names
###############################################################################


_STAGE_DIRECTORIES = (
    "raw",
    "recon",
    "enum",
    "vuln",
    "exploit",
    "post",
    "findings",
    "correlated",
    "report",
)


###############################################################################
# Run Identity
###############################################################################


def create_run_id() -> str:
    """
    Create a unique UTC assessment run identifier.

    The timestamp keeps run directories human-readable while the short UUID
    suffix prevents collisions when multiple assessments start within the
    same millisecond.

    Example:

        20260831_153421_381_a4f9c2d1
    """

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S_%f"
    )[:-3]

    suffix = uuid4().hex[:8]

    return (
        f"{timestamp}_{suffix}"
    )


###############################################################################
# Output Directory Initialization
###############################################################################


def init_output_dirs(
    base_dir: str,
    target_name: str,
    *,
    run_id: str | None = None,
) -> str:
    """
    Create an immutable per-assessment output directory.

    Layout:

        <base_dir>/
            <target_name>/
                <run_id>/
                    raw/
                    recon/
                    enum/
                    vuln/
                    exploit/
                    post/
                    findings/
                    correlated/
                    report/

    Args:
        base_dir:
            Root output directory.

        target_name:
            Filesystem-safe target directory name.

        run_id:
            Optional pre-generated assessment run identifier. When omitted,
            a new unique identifier is generated.

    Returns:
        Absolute output directory path as a string.
    """

    resolved_run_id = (
        str(
            run_id
        ).strip()
        if run_id
        else create_run_id()
    )

    if not resolved_run_id:
        raise ValueError(
            "run_id cannot be empty."
        )

    outdir = (
        Path(
            base_dir
        )
        / str(
            target_name
        ).strip()
        / resolved_run_id
    )

    if not outdir.name:
        raise ValueError(
            "target_name cannot be empty."
        )

    ensure_dir(
        str(
            outdir
        )
    )

    for directory in _STAGE_DIRECTORIES:
        ensure_dir(
            str(
                outdir
                / directory
            )
        )

    return str(
        outdir.resolve()
    )


###############################################################################
# Pipeline Paths
###############################################################################


def pipeline_paths(
    outdir: str,
) -> dict[str, str]:
    """
    Return canonical pipeline file and directory paths.

    This function is the single source of truth for files and directories
    exchanged between workflow stages.
    """

    root = Path(
        outdir
    )

    recon = (
        root
        / "recon"
    )

    findings = (
        root
        / "findings"
    )

    correlated = (
        root
        / "correlated"
    )

    report = (
        root
        / "report"
    )

    return {
        "hosts_raw": str(
            recon
            / "hosts_raw.txt"
        ),
        "hosts_alive": str(
            recon
            / "hosts_alive.txt"
        ),
        "hosts_final": str(
            recon
            / "hosts_final.txt"
        ),
        "urls_raw": str(
            recon
            / "urls_raw.txt"
        ),
        "urls_final": str(
            recon
            / "urls_final.txt"
        ),
        "findings_dir": str(
            findings
        ),
        "correlated_dir": str(
            correlated
        ),
        "report_dir": str(
            report
        ),
    }


###############################################################################
# Public API
###############################################################################


__all__ = [
    "create_run_id",
    "init_output_dirs",
    "pipeline_paths",
]
