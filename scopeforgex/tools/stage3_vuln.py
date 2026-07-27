"""
ScopeForgeX v0.4.0
Stage 3 - Vulnerability Assessment

Features
--------
* Shared vulnerability scanner framework
* Safe command construction
* Output validation
* Multi-input support
* Unified logging
* Automatic result merging
* Easier future scanner integration
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed

###############################################################################
# Nuclei Profiles
###############################################################################

NUCLEI_FAST_FLAGS = (
    "-severity high,critical "
    "-rate-limit 30 "
    "-timeout 5 "
    "-retries 1"
)

###############################################################################
# Helper Functions
###############################################################################


def _vuln_directory(ctx: dict) -> Path:
    """
    Return vulnerability output directory.
    """

    directory = Path(ctx["outdir"]) / "vuln"
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )
    return directory


def _safe_exists(path: Path) -> bool:
    """
    True when a file exists and contains data.
    """

    return (
        path.exists()
        and path.stat().st_size > 0
    )


def _quote(value: str) -> str:
    """
    Safe shell quoting.
    """

    return shlex.quote(value)


def _pipeline_file(
    ctx: dict,
    key: str,
) -> Path | None:
    """
    Return a pipeline artifact if available.
    """

    pipeline = ctx.get(
        "pipeline",
        {},
    )

    filename = pipeline.get(key)

    if not filename:
        return None

    path = Path(filename)

    if not path.exists():
        return None

    if path.stat().st_size == 0:
        return None

    return path


###############################################################################
# Result Helpers
###############################################################################


def _merge_results(
    inputs: Iterable[Path],
    output: Path,
) -> int:
    """
    Merge and deduplicate findings.
    """

    findings: list[str] = []

    for path in inputs:

        if not _safe_exists(path):
            continue

        with path.open(
            encoding="utf-8",
            errors="ignore",
        ) as infile:

            findings.extend(
                line.strip()
                for line in infile
                if line.strip()
            )

    findings = list(
        dict.fromkeys(findings)
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as outfile:

        if findings:
            outfile.write(
                "\n".join(findings)
            )
            outfile.write("\n")

    return len(findings)


###############################################################################
# Base Scanner
###############################################################################


class VulnerabilityScanner(ToolBase):
    """
    Shared functionality for Stage-3 scanners.
    """

    stage = 3
    risk = "medium"

    def vuln_dir(
        self,
        ctx: dict,
    ) -> Path:
        return _vuln_directory(ctx)

    def output(
        self,
        ctx: dict,
        filename: str,
    ) -> Path:
        return self.vuln_dir(ctx) / filename

    def pipeline_input(
        self,
        ctx: dict,
        key: str,
    ) -> Path | None:
        return _pipeline_file(
            ctx,
            key,
        )

    def tool_missing(
        self,
    ) -> ToolResult:

        return ToolResult(
            self.name,
            False,
            [],
            f"{self.name} not installed",
        )

    def ensure_output(
        self,
        path: Path,
    ) -> None:
        """
        Always create an output file.
        """

        if not path.exists():
            path.touch()
###############################################################################
# Nuclei Scanner
###############################################################################


class NucleiTool(VulnerabilityScanner):
    """
    Fast Nuclei vulnerability assessment.

    Scans:
        • Alive hosts
        • Discovered URLs

    Produces:
        nuclei_hosts.txt
        nuclei_urls.txt
        nuclei.txt
        nuclei_hosts.log
        nuclei_urls.log
    """

    name = "nuclei"
    description = (
        "FAST: Scan alive hosts and discovered URLs using Nuclei"
    )

    def _scan(
        self,
        input_file: Path | None,
        output_file: Path,
        logfile: Path,
    ) -> bool:
        """
        Execute a single Nuclei scan.

        Returns
        -------
        bool
            True if a scan was started.
        """

        if input_file is None:
            self.ensure_output(output_file)
            return False

        command = (
            "nuclei "
            f"-l {_quote(str(input_file))} "
            f"{NUCLEI_FAST_FLAGS} "
            f"-o {_quote(str(output_file))}"
        )

        run_cmd(
            command,
            outfile=str(logfile),
            timeout=600,
        )

        self.ensure_output(output_file)

        return True

    def run(
        self,
        ctx: dict,
    ) -> ToolResult:

        if not is_tool_installed("nuclei"):
            return self.tool_missing()

        hosts_input = self.pipeline_input(
            ctx,
            "hosts_final",
        )

        urls_input = self.pipeline_input(
            ctx,
            "urls_final",
        )

        hosts_output = self.output(
            ctx,
            "nuclei_hosts.txt",
        )

        urls_output = self.output(
            ctx,
            "nuclei_urls.txt",
        )

        merged_output = self.output(
            ctx,
            "nuclei.txt",
        )

        hosts_log = self.output(
            ctx,
            "nuclei_hosts.log",
        )

        urls_log = self.output(
            ctx,
            "nuclei_urls.log",
        )

        scanned_inputs = 0

        if self._scan(
            hosts_input,
            hosts_output,
            hosts_log,
        ):
            scanned_inputs += 1

        if self._scan(
            urls_input,
            urls_output,
            urls_log,
        ):
            scanned_inputs += 1

        total_findings = _merge_results(
            [
                hosts_output,
                urls_output,
            ],
            merged_output,
        )

        notes = (
            f"Nuclei completed against "
            f"{scanned_inputs} input source(s). "
            f"{total_findings} unique finding(s)."
        )

        if not _safe_exists(merged_output):
            notes += (
                " No confirmed findings were produced."
            )

        return ToolResult(
            self.name,
            True,
            [
                str(merged_output),
                str(hosts_output),
                str(urls_output),
                str(hosts_log),
                str(urls_log),
            ],
            notes,
        )
###############################################################################
# Tool Registration
###############################################################################


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]


###############################################################################
# Public Exports
###############################################################################

__all__ = [
    "NUCLEI_FAST_FLAGS",
    "NucleiTool",
    "ALL_STAGE3_VULN_TOOLS",
]
