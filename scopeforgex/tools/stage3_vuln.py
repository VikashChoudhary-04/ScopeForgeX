"""
ScopeForgeX v0.5.0
Stage 3 - Vulnerability Assessment

Features
--------
* Shared vulnerability scanner framework
* Structured ExecutionResult handling
* Finding collection
* Artifact tracking
* Multi-input support
* Unified logging
* Automatic result merging
"""

from __future__ import annotations

import shlex

from pathlib import Path
from typing import Iterable

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
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


def _vuln_directory(
    ctx: dict,
) -> Path:
    """
    Return vulnerability output directory.
    """

    directory = (
        Path(ctx["outdir"])
        / "vuln"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _safe_exists(
    path: Path,
) -> bool:
    """
    True when a file exists and contains data.
    """

    return (
        path.exists()
        and path.stat().st_size > 0
    )


def _quote(
    value: str,
) -> str:
    """
    Safe shell quoting.
    """

    return shlex.quote(
        value
    )


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

    filename = pipeline.get(
        key
    )

    if not filename:
        return None

    path = Path(
        filename
    )

    if not path.exists():
        return None

    if path.stat().st_size == 0:
        return None

    return path


###############################################################################
# Finding Helpers
###############################################################################


def _merge_results(
    inputs: Iterable[Path],
    output: Path,
) -> list[str]:
    """
    Merge and deduplicate findings.

    Returns:
        List of unique findings.
    """

    findings: list[str] = []

    for path in inputs:

        if not _safe_exists(
            path
        ):
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
        dict.fromkeys(
            findings
        )
    )

    with output.open(
        "w",
        encoding="utf-8",
    ) as outfile:

        if findings:

            outfile.write(
                "\n".join(
                    findings
                )
            )

            outfile.write(
                "\n"
            )

    return findings
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

        return _vuln_directory(
            ctx
        )

    def output(
        self,
        ctx: dict,
        filename: str,
    ) -> Path:

        return (
            self.vuln_dir(ctx)
            /
            filename
        )

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
    ) -> ExecutionResult:

        return ExecutionResult.failure(
            tool=self.name,
            capability="vulnerability_scanning",
            error=f"{self.name} not installed",
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

        Returns:
            True if scan started.
        """

        if input_file is None:

            self.ensure_output(
                output_file
            )

            return False

        command = (
            "nuclei "
            f"-l {_quote(str(input_file))} "
            f"{NUCLEI_FAST_FLAGS} "
            f"-o {_quote(str(output_file))}"
        )

        run_command(
            tool=self.name,
            capability="vulnerability_scanning",
            cmd=command,
            outfile=str(logfile),
            timeout=600,
        )

        self.ensure_output(
            output_file
        )

        return True


    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        if not is_tool_installed(
            "nuclei"
        ):

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


        findings = _merge_results(
            [
                hosts_output,
                urls_output,
            ],
            merged_output,
        )


        artifacts = [
            merged_output,
            hosts_output,
            urls_output,
            hosts_log,
            urls_log,
        ]


        return ExecutionResult.success_result(
            tool=self.name,
            capability="vulnerability_scanning",
            artifacts=artifacts,
            findings=findings,
            metadata={
                "scanned_sources": scanned_inputs,
                "finding_count": len(findings),
                "message": (
                    "Nuclei vulnerability assessment completed."
                ),
            },
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
