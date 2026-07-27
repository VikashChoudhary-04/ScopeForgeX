"""
ScopeForgeX Stage 3
===================

Vulnerability Assessment Stage

Responsibilities
----------------
* Run Nuclei vulnerability scanning
* Scan discovered hosts and URLs
* Produce parser-ready JSONL output
* Aggregate vulnerability results
* Store vulnerability artifacts

v0.6.1
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: Path,
) -> int:
    """
    Count non-empty lines in a file.
    """

    if not path.exists():
        return 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        return sum(
            1
            for line in file
            if line.strip()
        )



def _merge_files(
    sources: list[Path],
    destination: Path,
) -> None:
    """
    Merge scanner output files.
    """

    with destination.open(
        "w",
        encoding="utf-8",
    ) as output:

        for source in sources:

            if not source.exists():
                continue

            content = source.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            if content.strip():

                output.write(
                    content
                )

                if not content.endswith(
                    "\n"
                ):

                    output.write(
                        "\n"
                    )



###############################################################################
# Nuclei Scanner
###############################################################################


class NucleiTool(
    ToolBase
):

    name = "nuclei"

    stage = 3

    description = (
        "Nuclei vulnerability assessment"
    )

    risk = "low"



    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute Nuclei scans.
        """

        if ctx.get(
            "target_type"
        ) != "web":

            return ExecutionResult.skipped(
                tool=self.name,
                capability="vulnerability_scanning",
                reason="Skipped (not web target)",
            )


        if not is_tool_installed(
            "nuclei"
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability="vulnerability_scanning",
                error="nuclei not installed",
            )


        recon_dir = Path(
            ctx["outdir"]
        ) / "recon"


        vuln_dir = Path(
            ctx["outdir"]
        ) / "vuln"


        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )


        hosts_file = (
            recon_dir /
            "hosts_final.txt"
        )

        urls_file = (
            recon_dir /
            "urls_final.txt"
        )


        hosts_output = (
            vuln_dir /
            "nuclei_hosts.jsonl"
        )

        urls_output = (
            vuln_dir /
            "nuclei_urls.jsonl"
        )

        merged_output = (
            vuln_dir /
            "nuclei.txt"
        )


        hosts_log = (
            vuln_dir /
            "nuclei_hosts.log"
        )

        urls_log = (
            vuln_dir /
            "nuclei_urls.log"
        )


        artifacts = []


        if _count_lines(
            hosts_file
        ):

            run_cmd(

                (
                    f"nuclei "
                    f"-l {hosts_file} "
                    f"-severity high,critical "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {hosts_output}"
                ),

                outfile=str(
                    hosts_log
                ),

                timeout=900,

            )


            artifacts.extend(
                [
                    str(hosts_output),
                    str(hosts_log),
                ]
            )


        if _count_lines(
            urls_file
        ):

            run_cmd(

                (
                    f"nuclei "
                    f"-l {urls_file} "
                    f"-severity high,critical "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {urls_output}"
                ),

                outfile=str(
                    urls_log
                ),

                timeout=900,

            )


            artifacts.extend(
                [
                    str(urls_output),
                    str(urls_log),
                ]
            )


        _merge_files(
            [
                hosts_output,
                urls_output,
            ],
            merged_output,
        )


        artifacts.append(
            str(
                merged_output
            )
        )


        finding_count = _count_lines(
            merged_output
        )


        return ExecutionResult.success_result(
            tool=self.name,
            capability="vulnerability_scanning",
            artifacts=artifacts,
            metadata={
                "scanned_sources": 2,
                "finding_count": finding_count,
                "message":
                    "Nuclei vulnerability assessment completed.",
            },
        )



###############################################################################
# Stage Entry Point
###############################################################################


def stage3_vuln(
    ctx: dict,
) -> ExecutionResult:
    """
    Execute Stage 3 vulnerability assessment.
    """

    result = NucleiTool().run(
        ctx
    )


    ctx.setdefault(
        "tool_results",
        [],
    ).append(
        result
    )


    return result



###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiTool",
    "stage3_vuln",
]
