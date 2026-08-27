"""
ScopeForgeX Stage 6
===================

Reporting & Cleanup Stage

Responsibilities
----------------
- Collect workflow metadata
- Discover generated artifacts
- Parse vulnerability scanner output
- Convert canonical runtime phase results into reporting results
- Build ReportData
- Generate Markdown + JSON reports

RuntimeState is the authoritative source of workflow execution history.

v1.1.0
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
from reporting.json_exporter import export_json_report
from reporting.parsers.nuclei_parser import parse_nuclei

from scopeforgex.runtime import AssessmentPhase
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


def _discover_artifacts(
    outdir: Path,
) -> list[str]:
    """
    Discover generated files inside the workflow output directory.

    Report files themselves are excluded so that files_generated represents
    scan artifacts rather than the reports currently being generated.
    """

    if not outdir.exists():
        return []

    artifacts: list[str] = []

    excluded = {
        "report.md",
        "report.json",
    }

    for path in outdir.rglob("*"):

        if not path.is_file():
            continue

        if ".gitkeep" in str(path):
            continue

        relative = path.relative_to(
            outdir
        )

        if relative.name in excluded:
            continue

        artifacts.append(
            str(relative)
        )

    return sorted(
        artifacts
    )


###############################################################################
# Reporting Stage
###############################################################################


class ReportingStage:
    """
    Builds final ScopeForgeX reports.
    """

    def __init__(
        self,
        ctx: dict,
    ) -> None:

        self.ctx = ctx

        self.outdir = Path(
            ctx["outdir"]
        )

        self.report_path = (
            self.outdir / "report.md"
        )

        self.json_path = (
            self.outdir / "report.json"
        )

        self.artifacts: list[str] = []

    ###########################################################################
    # Artifact Paths
    ###########################################################################

    def artifact_paths(
        self,
    ) -> dict[str, Path]:

        recon = self.outdir / "recon"
        vuln = self.outdir / "vuln"

        return {
            "hosts_raw":
                recon / "hosts_raw.txt",

            "hosts_alive":
                recon / "hosts_alive.txt",

            "hosts_final":
                recon / "hosts_final.txt",

            "urls_final":
                recon / "urls_final.txt",

            "nuclei":
                vuln / "nuclei.txt",
        }

    ###########################################################################
    # Statistics
    ###########################################################################

    def statistics(
        self,
    ) -> ScanStatistics:
        """
        Build workflow statistics.

        Filesystem-derived metrics describe generated scan artifacts.

        Runtime-derived metrics describe actual execution history.

        RuntimeState is the authoritative source for execution metrics.
        """

        files = self.artifact_paths()

        self.artifacts = _discover_artifacts(
            self.outdir
        )

        runtime = self.ctx.get(
            "runtime"
        )

        tools_executed = 0
        stages_executed = 0
        stages_skipped = 0

        if runtime is not None:

            tool_results = getattr(
                runtime,
                "tool_results",
                [],
            )

            stage_results = getattr(
                runtime,
                "stage_results",
                [],
            )

            tools_executed = len(
                tool_results
            )

            for result in stage_results:

                if getattr(
                    result,
                    "success",
                    False,
                ):
                    stages_executed += 1
                else:
                    stages_skipped += 1

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

            stages_executed=stages_executed,

            stages_skipped=stages_skipped,

            tools_executed=tools_executed,
        )

    ###########################################################################
    # Findings
    ###########################################################################

    def findings(
        self,
    ):
        """
        Parse vulnerability scanner findings.
        """

        nuclei_file = (
            self.artifact_paths()["nuclei"]
        )

        if not nuclei_file.exists():
            return []

        return parse_nuclei(
            str(
                nuclei_file
            )
        )

    ###########################################################################
    # Stage Results
    ###########################################################################

    def _stage_results(
        self,
    ) -> list[StageResult]:
        """
        Convert canonical runtime phase results into reporting results.

        RuntimeState is the authoritative source of execution history.

        Stage 6 does not reconstruct phases from filesystem artifacts and
        does not consume legacy ctx["stage_results"] data.

        The runtime StageResult and reporting StageResult are deliberately
        separate models: runtime owns execution state, while reporting owns
        the report representation.
        """

        runtime = self.ctx.get(
            "runtime"
        )

        if runtime is None:
            return []

        runtime_results = getattr(
            runtime,
            "stage_results",
            [],
        )

        output: list[StageResult] = []

        for result in runtime_results:

            phase = getattr(
                result,
                "phase",
                None,
            )

            if phase is None:
                continue

            if not isinstance(
                phase,
                AssessmentPhase,
            ):
                continue

            status = (
                "Completed"
                if getattr(
                    result,
                    "success",
                    False,
                )
                else "Failed"
            )

            output.append(
                StageResult(
                    phase=phase,
                    status=status,
                )
            )

        return output

    ###########################################################################
    # Tool Results
    ###########################################################################

    def _tool_results(
        self,
    ) -> dict[str, str]:
        """
        Build a report-friendly tool execution summary from RuntimeState.

        RuntimeState is the authoritative source of tool execution history.
        """

        runtime = self.ctx.get(
            "runtime"
        )

        if runtime is None:
            return {}

        results = getattr(
            runtime,
            "tool_results",
            [],
        )

        output: dict[str, str] = {}

        for result in results:

            tool = str(
                getattr(
                    result,
                    "tool",
                    "",
                )
            ).strip()

            if not tool:
                continue

            output[tool] = (
                "Completed"
                if getattr(
                    result,
                    "success",
                    False,
                )
                else "Failed"
            )

        return output

    ###########################################################################
    # Build Report
    ###########################################################################

    def build_report(
        self,
    ) -> ReportData:
        """
        Build the canonical ReportData object.

        RuntimeState supplies execution history while filesystem artifacts
        supply scan-specific discovery and finding data.
        """

        start = self.ctx.get(
            "workflow_start_time",
            time.time(),
        )

        end = self.ctx.get(
            "workflow_end_time",
            time.time(),
        )

        statistics = self.statistics()

        findings = self.findings()

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
                start
            ),

            end_time=datetime.fromtimestamp(
                end
            ),

            statistics=statistics,

            generated_files=list(
                self.artifacts
            ),

            stages=self._stage_results(),

            tool_results=self._tool_results(),
        )

        report.duration_seconds = (
            end - start
        )

        report.findings = findings

        return report

    ###########################################################################
    # Generate
    ###########################################################################

    def generate(
        self,
    ) -> ReportData:
        """
        Generate Markdown and JSON reports.
        """

        report = self.build_report()

        ReportGenerator(
            report
        ).generate_markdown(
            str(
                self.report_path
            )
        )

        export_json_report(
            report,
            str(
                self.json_path
            ),
        )

        return report


###############################################################################
# Public Stage Entry Point
###############################################################################


def stage6_reporting(
    ctx: dict,
) -> None:
    """
    Execute the ScopeForgeX-native reporting phase.
    """

    stage(
        "PHASE 6 — REPORTING",
        "green",
    )

    reporting = ReportingStage(
        ctx
    )

    reporting.generate()

    ok(
        f"Reports written to {reporting.outdir}"
    )


__all__ = [
    "ReportingStage",
    "stage6_reporting",
]
