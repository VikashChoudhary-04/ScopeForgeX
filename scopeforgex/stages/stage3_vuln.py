"""
ScopeForgeX Stage 3
===================

Vulnerability Assessment Stage

Responsibilities
----------------
* Run Nuclei vulnerability scanning
* Scan discovered hosts and URLs
* Produce parser-ready JSONL output
* Aggregate findings
* Store vulnerability artifacts

v0.6.1
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _merge_files(
    files: list[Path],
    output: Path,
) -> None:
    """
    Merge nuclei outputs into a single file.
    """

    with output.open(
        "w",
        encoding="utf-8",
    ) as outfile:

        for file in files:

            if not file.exists():
                continue

            content = file.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            if content.strip():

                outfile.write(
                    content
                )

                if not content.endswith("\n"):

                    outfile.write(
                        "\n"
                    )



def _count_lines(
    path: Path,
) -> int:

    if not path.exists():
        return 0

    return sum(
        1
        for line in path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        )
        if line.strip()
    )


###############################################################################
# Nuclei Tool
###############################################################################


class NucleiTool(ToolBase):

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



        hosts = (
            recon_dir /
            "hosts_final.txt"
        )

        urls = (
            recon_dir /
            "urls_final.txt"
        )



        host_output = (
            vuln_dir /
            "nuclei_hosts.jsonl"
        )

        url_output = (
            vuln_dir /
            "nuclei_urls.jsonl"
        )

        merged_output = (
            vuln_dir /
            "nuclei.txt"
        )



        host_log = (
            vuln_dir /
            "nuclei_hosts.log"
        )

        url_log = (
            vuln_dir /
            "nuclei_urls.log"
        )



        artifacts = []



        if hosts.exists() and _count_lines(hosts):

            run_cmd(

                (
                    f"nuclei "
                    f"-l {hosts} "
                    f"-severity high,critical "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {host_output}"
                ),

                outfile=str(
                    host_log
                ),

                timeout=900,
            )


            artifacts.extend(
                [
                    str(host_output),
                    str(host_log),
                ]
            )



        if urls.exists() and _count_lines(urls):

            run_cmd(

                (
                    f"nuclei "
                    f"-l {urls} "
                    f"-severity high,critical "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {url_output}"
                ),

                outfile=str(
                    url_log
                ),

                timeout=900,
            )


            artifacts.extend(
                [
                    str(url_output),
                    str(url_log),
                ]
            )



        _merge_files(
            [
                host_output,
                url_output,
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

                "finding_count":
                    finding_count,

                "message":
                    (
                        "Nuclei vulnerability "
                        "assessment completed."
                    ),

            },

        )



###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiTool",
]
