"""
Enhanced Report Generator (v2 Skeleton)

NOTE:
This version expands the report layout while remaining compatible with the
previous architecture. It is intended as a drop-in replacement for
report_generator.py after ReportData has been expanded.
"""

from pathlib import Path
from datetime import datetime
from .models import ReportData


class ReportGenerator:
    def __init__(self, report: ReportData):
        self.report = report

    def _line(self, lines, text=""):
        lines.append(text + "\n")

    def generate_markdown(self, output_file: str):
        r = self.report
        lines = []

        self._line(lines, "# ScopeForgeX Assessment Report")
        self._line(lines)

        self._line(lines, "## Assessment Summary")
        self._line(lines, f"- **Target:** `{r.target}`")
        self._line(lines, f"- **Profile:** `{r.profile}`")
        self._line(lines, f"- **Target Type:** `{r.target_type}`")

        if getattr(r, "start_time", None):
            self._line(lines, f"- **Started:** {r.start_time}")
        if getattr(r, "end_time", None):
            self._line(lines, f"- **Finished:** {r.end_time}")
        if hasattr(r, "duration_seconds"):
            self._line(lines, f"- **Duration:** {r.duration_seconds:.2f} seconds")

        self._line(lines)

        self._line(lines, "## Workflow Execution")
        self._line(lines, "| Stage | Status |")
        self._line(lines, "|------|--------|")
        for stage in getattr(r, "stages", []):
            self._line(lines, f"| {stage.name} | {stage.status} |")
        self._line(lines)

        stats = r.statistics
        self._line(lines, "## Workflow Statistics")
        for label, value in [
            ("Subdomains discovered", stats.subdomains_found),
            ("Alive hosts", stats.alive_hosts),
            ("Validated hosts", stats.final_hosts),
            ("URLs discovered", stats.urls_discovered),
            ("Nuclei findings", stats.nuclei_findings),
            ("Files generated", stats.files_generated),
        ]:
            self._line(lines, f"- {label}: **{value}**")
        self._line(lines)

        if getattr(r, "tool_results", None):
            self._line(lines, "## Tool Execution")
            self._line(lines, "| Tool | Status |")
            self._line(lines, "|------|--------|")
            for tool, status in r.tool_results.items():
                self._line(lines, f"| {tool} | {status} |")
            self._line(lines)

        if r.generated_files:
            self._line(lines, "## Generated Artifacts")
            for f in r.generated_files:
                self._line(lines, f"- `{Path(f).name}`")
            self._line(lines)

        if getattr(r, "warnings", None):
            self._line(lines, "## Execution Notes")
            for w in r.warnings:
                self._line(lines, f"- {w}")
            self._line(lines)

        self._line(lines, "## Analyst Guidance")
        self._line(lines, "- Review skipped stages.")
        self._line(lines, "- Validate automated findings manually.")
        self._line(lines, "- Re-run using FULL_SAFE if required.")

        Path(output_file).write_text("".join(lines), encoding="utf-8")
