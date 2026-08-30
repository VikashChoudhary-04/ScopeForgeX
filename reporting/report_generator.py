"""
ScopeForgeX Report Generator
============================

Markdown report renderer for the canonical ScopeForgeX reporting models.

Responsibilities
----------------
- Render assessment metadata
- Render canonical assessment phases
- Render workflow statistics
- Render tool execution results
- Render generated artifacts
- Render execution notes
- Write the final Markdown report

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from pathlib import Path

from .models import ReportData


class ReportGenerator:
    """
    Generate Markdown reports from ReportData.
    """

    def __init__(
        self,
        report: ReportData,
    ) -> None:

        self.report = report

    # ------------------------------------------------------------------
    # Markdown Helpers
    # ------------------------------------------------------------------

    def _line(
        self,
        lines: list[str],
        text: str = "",
    ) -> None:

        lines.append(
            text + "\n"
        )

    # ------------------------------------------------------------------
    # Generate
    # ------------------------------------------------------------------

    def generate_markdown(
        self,
        output_file: str,
    ) -> None:
        """
        Generate a Markdown assessment report.
        """

        report = self.report

        lines: list[str] = []

        # --------------------------------------------------------------
        # Header
        # --------------------------------------------------------------

        self._line(
            lines,
            "# ScopeForgeX Assessment Report",
        )

        self._line(
            lines
        )

        # --------------------------------------------------------------
        # Assessment Summary
        # --------------------------------------------------------------

        self._line(
            lines,
            "## Assessment Summary",
        )

        self._line(
            lines,
            f"- **Target:** `{report.target}`",
        )

        self._line(
            lines,
            f"- **Profile:** `{report.profile}`",
        )

        self._line(
            lines,
            f"- **Target Type:** `{report.target_type}`",
        )

        if getattr(
            report,
            "start_time",
            None,
        ):

            self._line(
                lines,
                (
                    f"- **Started:** "
                    f"{report.start_time}"
                ),
            )

        if getattr(
            report,
            "end_time",
            None,
        ):

            self._line(
                lines,
                (
                    f"- **Finished:** "
                    f"{report.end_time}"
                ),
            )

        if hasattr(
            report,
            "duration_seconds",
        ):

            self._line(
                lines,
                (
                    f"- **Duration:** "
                    f"{report.duration_seconds:.2f} "
                    "seconds"
                ),
            )

        self._line(
            lines
        )

        # --------------------------------------------------------------
        # Workflow Execution
        # --------------------------------------------------------------

        self._render_workflow(
            lines
        )

        # --------------------------------------------------------------
        # Workflow Statistics
        # --------------------------------------------------------------

        self._render_statistics(
            lines
        )

        # --------------------------------------------------------------
        # Tool Execution
        # --------------------------------------------------------------

        self._render_tools(
            lines
        )

        # --------------------------------------------------------------
        # Generated Artifacts
        # --------------------------------------------------------------

        self._render_artifacts(
            lines
        )

        # --------------------------------------------------------------
        # Execution Notes
        # --------------------------------------------------------------

        self._render_notes(
            lines
        )

        # --------------------------------------------------------------
        # Analyst Guidance
        # --------------------------------------------------------------

        self._render_guidance(
            lines
        )

        # --------------------------------------------------------------
        # Write
        # --------------------------------------------------------------

        Path(
            output_file
        ).write_text(
            "".join(lines),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Workflow
    # ------------------------------------------------------------------

    def _render_workflow(
        self,
        lines: list[str],
    ) -> None:
        """
        Render canonical assessment-phase execution results.

        Reporting StageResult uses AssessmentPhase as its lifecycle
        identifier. The legacy ``stage.name`` field is intentionally
        no longer consumed.
        """

        self._line(
            lines,
            "## Workflow Execution",
        )

        self._line(
            lines,
            "| Phase | Status |",
        )

        self._line(
            lines,
            "|-------|--------|",
        )

        for stage in getattr(
            self.report,
            "stages",
            [],
        ):

            phase = getattr(
                stage,
                "phase",
                None,
            )

            if phase is None:
                continue

            phase_name = getattr(
                phase,
                "value",
                str(phase),
            )

            status = getattr(
                stage,
                "status",
                "Unknown",
            )

            self._line(
                lines,
                (
                    f"| {phase_name} | "
                    f"{status} |"
                ),
            )

        self._line(
            lines
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def _render_statistics(
        self,
        lines: list[str],
    ) -> None:
        """
        Render workflow statistics.
        """

        stats = self.report.statistics

        self._line(
            lines,
            "## Workflow Statistics",
        )

        statistics = [
            (
                "Subdomains discovered",
                getattr(
                    stats,
                    "subdomains_found",
                    0,
                ),
            ),
            (
                "Alive hosts",
                getattr(
                    stats,
                    "alive_hosts",
                    0,
                ),
            ),
            (
                "Validated hosts",
                getattr(
                    stats,
                    "final_hosts",
                    0,
                ),
            ),
            (
                "URLs discovered",
                getattr(
                    stats,
                    "urls_discovered",
                    0,
                ),
            ),
            (
                "Nuclei findings",
                getattr(
                    stats,
                    "nuclei_findings",
                    0,
                ),
            ),
            (
                "Files generated",
                getattr(
                    stats,
                    "files_generated",
                    0,
                ),
            ),
            (
                "Tools executed",
                getattr(
                    stats,
                    "tools_executed",
                    0,
                ),
            ),
            (
                "Stages executed",
                getattr(
                    stats,
                    "stages_executed",
                    0,
                ),
            ),
            (
                "Stages skipped",
                getattr(
                    stats,
                    "stages_skipped",
                    0,
                ),
            ),
        ]

        for label, value in statistics:

            self._line(
                lines,
                f"- {label}: **{value}**",
            )

        self._line(
            lines
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def _render_tools(
        self,
        lines: list[str],
    ) -> None:
        """
        Render tool execution results.
        """

        tool_results = getattr(
            self.report,
            "tool_results",
            None,
        )

        if not tool_results:
            return

        self._line(
            lines,
            "## Tool Execution",
        )

        self._line(
            lines,
            "| Tool | Status |",
        )

        self._line(
            lines,
            "|------|--------|",
        )

        for tool, status in tool_results.items():

            self._line(
                lines,
                (
                    f"| {tool} | "
                    f"{status} |"
                ),
            )

        self._line(
            lines
        )

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def _render_artifacts(
        self,
        lines: list[str],
    ) -> None:
        """
        Render generated workflow artifacts.
        """

        generated_files = getattr(
            self.report,
            "generated_files",
            [],
        )

        if not generated_files:
            return

        self._line(
            lines,
            "## Generated Artifacts",
        )

        for file_path in generated_files:

            self._line(
                lines,
                (
                    f"- `{Path(file_path).name}`"
                ),
            )

        self._line(
            lines
        )

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def _render_notes(
        self,
        lines: list[str],
    ) -> None:
        """
        Render warnings and execution notes.
        """

        warnings = getattr(
            self.report,
            "warnings",
            [],
        )

        errors = getattr(
            self.report,
            "errors",
            [],
        )

        if not warnings and not errors:
            return

        self._line(
            lines,
            "## Execution Notes",
        )

        for warning in warnings:

            self._line(
                lines,
                f"- {warning}",
            )

        for error in errors:

            self._line(
                lines,
                f"- **Error:** {error}",
            )

        self._line(
            lines
        )

    # ------------------------------------------------------------------
    # Guidance
    # ------------------------------------------------------------------

    def _render_guidance(
        self,
        lines: list[str],
    ) -> None:
        """
        Render analyst guidance.
        """

        self._line(
            lines,
            "## Analyst Guidance",
        )

        self._line(
            lines,
            "- Review skipped stages.",
        )

        self._line(
            lines,
            (
                "- Validate automated findings "
                "manually."
            ),
        )

        self._line(
            lines,
            (
                "- Re-run using FULL_SAFE "
                "if required."
            ),
        )

        self._line(
            lines
        )


__all__ = [
    "ReportGenerator",
]
