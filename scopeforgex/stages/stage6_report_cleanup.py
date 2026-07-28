"""
ScopeForgeX Stage 6
===================

Reporting & Cleanup Stage

Responsibilities
----------------
* Collect workflow metadata
* Discover generated artifacts
* Parse vulnerability scanner output
* Build ReportData
* Generate Markdown + JSON reports

v1.0.0
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

from scopeforgex.ui import ok, stage


###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: Path | None,
) -> int:

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

    if not outdir.exists():
        return []

    artifacts = []

    for path in outdir.rglob("*"):

        if (
            path.is_file()
            and ".gitkeep" not in str(path)
        ):

            artifacts.append(
                str(
                    path.relative_to(outdir)
                )
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

        self.artifacts = []



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

        files = self.artifact_paths()


        self.artifacts = _discover_artifacts(
            self.outdir
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

        )



    ###########################################################################
    # Findings
    ###########################################################################

    def findings(
        self,
    ):

        nuclei_file = (
            self.artifact_paths()["nuclei"]
        )


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

        results = self.ctx.get(
            "stage_results",
            [],
        )


        output = []


        for result in results:

            output.append(

                StageResult(
                    getattr(
                        result,
                        "tool",
                        "Unknown",
                    ),

                    (
                        "Completed"
                        if getattr(
                            result,
                            "success",
                            False,
                        )
                        else "Failed"
                    ),
                )

            )


        output.append(

            StageResult(
                "Reporting",
                "Completed",
            )

        )


        return output



    ###########################################################################
    # Tool Results
    ###########################################################################

    def _tool_results(
        self,
    ):

        return self.ctx.get(
            "tool_results",
            [],
        )



    ###########################################################################
    # Build Report
    ###########################################################################

    def build_report(
        self,
    ) -> ReportData:


        stats = self.statistics()


        start = self.ctx.get(
            "workflow_start_time",
            time.time(),
        )


        end = self.ctx.get(
            "workflow_end_time",
            time.time(),
        )


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

            statistics=stats,

            generated_files=self.artifacts,

        )


        report.duration_seconds = (
            end - start
        )


        report.findings = findings


        report.stages = (
            self._stage_results()
        )


        report.tool_results = (
            self._tool_results()
        )


        report.warnings = []


        if not findings:

            report.warnings.append(
                "No automated vulnerability findings were recorded."
            )


        return report



    ###########################################################################
    # Generate Reports
    ###########################################################################

    def write_report(
        self,
    ) -> None:


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
            )

        )


        ok(
            f"Report written to {self.report_path}"
        )


        ok(
            f"JSON report written to {self.json_path}"
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
        ctx
    ).write_report()



__all__ = [
    "ReportingStage",
    "stage6_reporting",
]
