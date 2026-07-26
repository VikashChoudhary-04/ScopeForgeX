"""
ScopeForgeX Reporting Engine
============================

Markdown report renderer.
"""

from pathlib import Path
from .models import ReportData


class ReportGenerator:
    def __init__(self, report: ReportData):
        self.report = report

    def _write(self, lines, text=""):
        lines.append(text + "\n")

    def generate_markdown(self, output_file: str) -> None:
        r = self.report
        s = r.statistics
        lines = []

        self._write(lines, "# ScopeForgeX Assessment Report")
        self._write(lines)

        self._write(lines, "## Assessment Summary")
        self._write(lines, f"- **Target:** `{r.target}`")
        self._write(lines, f"- **Profile:** `{r.profile}`")
        self._write(lines, f"- **Target Type:** `{r.target_type}`")
        self._write(lines, f"- **Duration:** {r.duration_seconds:.2f} seconds")
        self._write(lines, f"- **Generated Artifacts:** {len(r.generated_files)}")
        self._write(lines)

        self._write(lines, "## Workflow Execution")
        self._write(lines, "| Stage | Status |")
        self._write(lines, "|------|--------|")
        for stage in r.stages:
            status = "✅ Completed" if stage.success else "❌ Failed"
            self._write(lines, f"| {stage.name} | {status} |")
        self._write(lines)

        self._write(lines, "## Workflow Statistics")
        self._write(lines, f"- Subdomains discovered: **{s.subdomains_found}**")
        self._write(lines, f"- Alive hosts: **{s.alive_hosts}**")
        self._write(lines, f"- Validated hosts passed downstream: **{s.final_hosts}**")
        self._write(lines, f"- Normalized URLs discovered: **{s.urls_discovered}**")
        self._write(lines, f"- Nuclei findings: **{s.nuclei_findings}**")
        self._write(lines, f"- Files generated: **{s.files_generated}**")
        self._write(lines)

        if r.generated_files:
            self._write(lines, "## Generated Artifacts")
            for f in r.generated_files:
                self._write(lines, f"- `{f}`")
            self._write(lines)

        if r.warnings:
            self._write(lines, "## Execution Notes")
            for warning in r.warnings:
                self._write(lines, f"- {warning}")
            self._write(lines)

        self._write(lines, "## Analyst Guidance")
        self._write(lines, "Automated findings should always be manually validated.")
        self._write(lines, "A report with no findings does not prove that the target is secure.")

        Path(output_file).write_text("".join(lines), encoding="utf-8")
