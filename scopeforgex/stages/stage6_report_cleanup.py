"""
ScopeForgeX Stage 6
===================

Professional Reporting & Cleanup Stage

v0.6.0

Responsibilities:
    - Collect workflow metadata
    - Discover generated artifacts
    - Collect findings
    - Calculate severity summary
    - Generate Markdown report
    - Generate JSON report
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
from reporting.findings import FindingCollector
from reporting.severity import calculate_summary, calculate_risk_rating

from scopeforgex.ui import (
    ok,
    stage,
)


###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: Path | None,
) -> int:
    """
    Count non-empty lines in file.
    """

    if path is None or not path.exists():

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
    Discover generated files.
    """

    if not outdir.exists():

        return []


    artifacts = []


    for path in outdir.rglob("*"):

        if (
            path.is_file()
            and ".gitkeep" not in str(path)
            and path.name not in (
                "report.md",
                "report.json",
            )
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
    Builds professional ScopeForgeX reports.
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
    # Statistics
    ###########################################################################

    def statistics(
        self,
    ) -> ScanStatistics:

        recon = self.outdir / "recon"

        vuln = self.outdir / "vuln"


        self.artifacts = _discover_artifacts(
            self.outdir
        )


        return ScanStatistics(

            subdomains_found=
                _count_lines(
                    recon / "hosts_raw.txt"
                ),

            alive_hosts=
                _count_lines(
                    recon / "hosts_alive.txt"
                ),

            final_hosts=
                _count_lines(
                    recon / "hosts_final.txt"
                ),

            urls_discovered=
                _count_lines(
                    recon / "urls_final.txt"
                ),

            nuclei_findings=
                _count_lines(
                    vuln / "nuclei.txt"
                ),

            files_generated=
                len(
                    self.artifacts
                ),
        )



    ###########################################################################
    # Findings
    ###########################################################################

    def findings(
        self,
    ):

        collector = FindingCollector()


        nuclei_files = [

            self.outdir
            / "vuln"
            / "nuclei.txt",

        ]


        for file in nuclei_files:

            collector.parse_nuclei_file(
                str(file)
            )


        return collector.all()



    ###########################################################################
    # Stage Results
    ###########################################################################

    def stages(
        self,
    ) -> list[StageResult]:

        results = []


        for item in self.ctx.get(
            "stage_results",
            [],
        ):

            results.append(

                StageResult(

                    name=getattr(
                        item,
                        "tool",
                        "Unknown",
                    ),

                    status=(

                        "Completed"

                        if getattr(
                            item,
                            "success",
                            False,
                        )

                        else "Failed"

                    ),
                )

            )


        results.append(

            StageResult(

                name="Reporting",

                status="Completed",

            )

        )


        return results



    ###########################################################################
    # Build Report
    ###########################################################################

    def build_report(
        self,
    ) -> ReportData:

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
                self.ctx.get(
                    "workflow_start_time",
                    time.time(),
                )
            ),

            end_time=datetime.fromtimestamp(
                self.ctx.get(
                    "workflow_end_time",
                    time.time(),
                )
            ),

            statistics=self.statistics(),

            generated_files=self.artifacts,

            stages=self.stages(),

            findings=findings,

        )


        report.duration_seconds = (

            self.ctx.get(
                "workflow_end_time",
                time.time(),
            )

            -

            self.ctx.get(
                "workflow_start_time",
                time.time(),
            )

        )


        report.severity_summary = (
            calculate_summary(
                findings
            )
        )


        report.tool_results = (
            self.ctx.get(
                "tool_results",
                {},
            )
        )


        report.warnings = []


        if not findings:

            report.warnings.append(
                "No automated vulnerability findings were recorded."
            )


        report.metadata.generator = (
            "ScopeForgeX"
        )


        return report



    ###########################################################################
    # Generate Reports
    ###########################################################################

    def write_reports(
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
            ),
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
    ).write_reports()



__all__ = [
    "ReportingStage",
    "stage6_reporting",
]
