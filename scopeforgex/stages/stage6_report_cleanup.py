"""
ScopeForgeX Stage 6
===================

Reporting & Cleanup Stage

Responsibilities
----------------
* Collect workflow metadata
* Discover generated artifacts
* Build ReportData
* Generate Markdown report

v0.4.0
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from reporting.models import (
    ReportData,
    ScanStatistics,
    StageResult,
)
from reporting.report_generator import ReportGenerator

from scopeforgex.ui import ok, stage

###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: Path | None,
) -> int:
    """
    Count non-empty lines in a file.
    """

    if path is None:
        return 0

    if not path.exists():
        return 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as handle:

        return sum(
            1
            for line in handle
            if line.strip()
        )


def _existing_files(
    paths: list[Path],
) -> list[str]:
    """
    Return existing file paths.
    """

    return [
        str(path)
        for path in paths
        if path.exists()
    ]


###############################################################################
# Reporting Stage
###############################################################################


class ReportingStage:
    """
    Builds the final assessment report.
    """

    def __init__(
        self,
        ctx: dict,
    ) -> None:

        self.ctx = ctx

        self.outdir = Path(
            ctx["outdir"]
        )

        self.recon_dir = (
            self.outdir / "recon"
        )

        self.vuln_dir = (
            self.outdir / "vuln"
        )

        self.report_path = (
            self.outdir / "report.md"
        )

    ###########################################################################
    # Artifact Discovery
    ###########################################################################

    def artifact_paths(
        self,
    ) -> dict[str, Path]:

        return {
            "hosts_raw":
                self.recon_dir / "hosts_raw.txt",

            "hosts_alive":
                self.recon_dir / "hosts_alive.txt",

            "hosts_final":
                self.recon_dir / "hosts_final.txt",

            "urls_final":
                self.recon_dir / "urls_final.txt",

            "nuclei":
                self.vuln_dir / "nuclei.txt",

            "nuclei_hosts":
                self.vuln_dir / "nuclei_hosts.txt",

            "nuclei_urls":
                self.vuln_dir / "nuclei_urls.txt",
        }

    ###########################################################################
    # Statistics
    ###########################################################################

    def statistics(
        self,
    ) -> ScanStatistics:

        files = self.artifact_paths()

        artifacts = _existing_files(
            list(
                files.values()
            )
        )

        self.artifacts = artifacts

        return ScanStatistics(
            subdomains_found=_count_lines(
                files["hosts_raw"]
            ),

            alive_hosts=_count_lines(
                files["hosts_alive"]
            ),

            final_hosts=_count_lines(
                files["hosts_final"]
            ),

            urls_discovered=_count_lines(
                files["urls_final"]
            ),

            nuclei_findings=_count_lines(
                files["nuclei"]
            ),

            files_generated=len(
                artifacts
            ),
        )
