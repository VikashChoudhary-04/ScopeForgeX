"""
ScopeForgeX Stage 6
===================

Reporting & Cleanup Stage

Responsibilities
----------------
* Consume RuntimeState execution data
* Collect workflow metadata
* Build ReportData
* Generate Markdown report

Runtime execution data is the primary source.
Filesystem discovery is used as a compatibility fallback.

v0.5.0
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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

        self.runtime = ctx.get(
            "runtime_state",
        )

        self.outdir = Path(
            ctx.get(
                "outdir",
                ".",
            )
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

        self.artifacts: list[str] = []


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


    def runtime_artifacts(
        self,
    ) -> list[str]:
        """
        Collect artifacts from RuntimeState.
        """

        if not self.runtime:
            return []

        artifacts = []

        for artifact in self.runtime.artifacts:

            path = getattr(
                artifact,
                "path",
                None,
            )

            if path:
                artifacts.append(
                    str(path)
                )

        return artifacts


    ###########################################################################
    # Statistics
    ###########################################################################

    def statistics(
        self,
    ) -> ScanStatistics:

        files = self.artifact_paths()

        discovered = _existing_files(
            list(
                files.values()
            )
        )

        runtime_files = self.runtime_artifacts()

        self.artifacts = list(
            dict.fromkeys(
                runtime_files + discovered
            )
        )

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
                self.artifacts
            ),

            stages_executed=(
                len(
                    self.runtime.stage_results
                )
                if self.runtime
                else 0
            ),

            tools_executed=(
                len(
                    self.runtime.tool_results
                )
                if self.runtime
                else 0
            ),
        )


    ###########################################################################
    # Report Construction
    ###########################################################################

    def build_report(
        self,
    ) -> ReportData:

        stats = self.statistics()

        start = self.ctx.get(
            "workflow_start_time",
            time.time(),
        )

        end = time.time()


        report = ReportData(

            target=self.ctx.get(
                "target",
                "-",
            ),

            profile=self.ctx.get(
                "profile",
                "-",
            ),

            target_type=self.ctx.get(
                "target_type",
                "-",
            ),

            start_time=datetime.fromtimestamp(
                start,
                tz=timezone.utc,
            ),

            end_time=datetime.fromtimestamp(
                end,
                tz=timezone.utc,
            ),

            statistics=stats,

            generated_files=self.artifacts,
        )


        report.duration_seconds = (
            end - start
        )


        report.stages = self._stage_results()

        report.tool_results = self._tool_results()

        report.warnings = self._warnings()


        return report


    ###########################################################################
    # Stage Summary
    ###########################################################################

    def _stage_results(
        self,
    ) -> list[StageResult]:

        if self.runtime:

            return [
                StageResult(
                    name=(
                        result.name
                    ),
                    status=(
                        "Completed"
                        if result.successful
                        else "Failed"
                    ),
                )

                for result
                in self.runtime.stage_results
            ]


        return [
            StageResult(
                "Scope",
                "Completed",
            ),
            StageResult(
                "Reconnaissance",
                "Completed",
            ),
            StageResult(
                "Validation",
                "Completed",
            ),
            StageResult(
                "Reporting",
                "Completed",
            ),
        ]


    ###########################################################################
    # Tool Summary
    ###########################################################################

    def _tool_results(
        self,
    ) -> dict[str, str]:

        if self.runtime:

            return {
                result.tool:
                    (
                        "Completed"
                        if result.success
                        else "Failed"
                    )

                for result
                in self.runtime.tool_results
            }


        return {}


    ###########################################################################
    # Warning Collection
    ###########################################################################

    def _warnings(
        self,
    ) -> list[str]:

        warnings: list[str] = []

        if self.runtime:

            warnings.extend(
                self.runtime.warnings
            )

            warnings.extend(
                self.runtime.errors
            )

        return warnings


    ###########################################################################
    # Report Generation
    ###########################################################################

    def write_report(
        self,
    ) -> None:

        report = self.build_report()

        ReportGenerator(
            report,
        ).generate_markdown(
            str(
                self.report_path
            )
        )

        ok(
            f"Report written to {self.report_path}"
        )


###############################################################################
# Public Entry Point
###############################################################################


def stage6_reporting(
    ctx: dict,
) -> None:

    stage(
        "STAGE 6 — REPORTING",
        "magenta",
    )

    ReportingStage(
        ctx,
    ).write_report()


__all__ = [
    "ReportingStage",
    "stage6_reporting",
]
