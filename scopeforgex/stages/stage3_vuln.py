"""
ScopeForgeX Stage 3
===================

Vulnerability Intelligence Stage

Responsibilities
----------------
* Execute Nuclei vulnerability scanning
* Support FAST and FULL_SAFE severity profiles
* Generate JSONL machine-readable output
* Aggregate findings
* Generate vulnerability summaries
* Preserve ExecutionResult compatibility

v0.6.3
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed

from scopeforgex.ui import (
    stage,
    ok,
    warn,
    info,
)


###############################################################################
# Result Display
###############################################################################


def _print_tool_result(
    result,
) -> None:
    """
    Display Stage 3 execution result.
    """

    if result.success:

        ok(
            f"Tool completed: {result.tool}"
        )

    else:

        warn(
            f"Tool failed/skipped: {result.tool}"
        )


    if result.metadata:

        for key, value in result.metadata.items():

            info(
                f"{key}: {value}"
            )


    if result.errors:

        for error in result.errors:

            warn(
                f"Error: {error}"
            )


    if result.warnings:

        for warning in result.warnings:

            warn(
                f"Warning: {warning}"
            )


    if result.artifacts:

        for artifact in result.artifacts:

            info(
                f"Artifact: {artifact}"
            )

    else:

        info(
            "Artifact: (none)"
        )


###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: Path,
) -> int:
    """
    Count non-empty lines.
    """

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



def _merge_files(
    sources: list[Path],
    destination: Path,
) -> None:
    """
    Merge Nuclei JSONL outputs.
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



def _analyse_findings(
    nuclei_file: Path,
) -> dict:
    """
    Analyse Nuclei JSONL output.
    """

    severity = Counter()

    templates = set()

    hosts = set()

    findings = 0


    if not nuclei_file.exists():

        return {
            "finding_count": 0,
            "severity": {},
            "templates": [],
            "hosts": [],
        }



    with nuclei_file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as handle:

        for line in handle:

            if not line.strip():

                continue


            try:

                data = json.loads(
                    line
                )

            except json.JSONDecodeError:

                continue


            findings += 1


            info_data = data.get(
                "info",
                {},
            )


            severity[
                info_data.get(
                    "severity",
                    "unknown",
                )
            ] += 1


            template = data.get(
                "template-id"
            )

            if template:

                templates.add(
                    template
                )


            host = data.get(
                "host"
            )

            if host:

                hosts.add(
                    host
                )


    return {
        "finding_count": findings,
        "severity": dict(severity),
        "templates": sorted(templates),
        "hosts": sorted(hosts),
    }


###############################################################################
# Nuclei Tool
###############################################################################


class NucleiTool(
    ToolBase
):

    name = "nuclei"

    stage = 3

    description = (
        "Nuclei vulnerability intelligence scanner"
    )

    risk = "low"



    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute Nuclei scanning.
        """

        if not is_tool_installed(
            "nuclei"
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability="vulnerability_scanning",
                error="nuclei not installed",
            )


        outdir = Path(
            ctx["outdir"]
        )


        recon = outdir / "recon"

        vuln = outdir / "vuln"


        vuln.mkdir(
            parents=True,
            exist_ok=True,
        )


        hosts = (
            recon /
            "hosts_final.txt"
        )


        urls = (
            recon /
            "urls_final.txt"
        )


        if ctx.get(
            "profile"
        ) == "full_safe":

            severity = (
                "info,low,medium,high,critical"
            )

        else:

            severity = (
                "high,critical"
            )
###############################################################################
# Nuclei Execution
###############################################################################


        hosts_json = (
            vuln /
            "nuclei_hosts.jsonl"
        )

        urls_json = (
            vuln /
            "nuclei_urls.jsonl"
        )

        all_json = (
            vuln /
            "nuclei_all.jsonl"
        )

        findings_file = (
            vuln /
            "nuclei_findings.txt"
        )

        summary_file = (
            vuln /
            "nuclei_summary.json"
        )


        artifacts = []


        if _count_lines(
            hosts
        ):

            run_cmd(
                (
                    f"nuclei "
                    f"-l {hosts} "
                    f"-severity {severity} "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {hosts_json}"
                ),
                outfile=str(
                    vuln /
                    "nuclei_hosts.log"
                ),
                timeout=900,
            )


            artifacts.extend(
                [
                    str(hosts_json),
                    str(
                        vuln /
                        "nuclei_hosts.log"
                    ),
                ]
            )


        if _count_lines(
            urls
        ):

            run_cmd(
                (
                    f"nuclei "
                    f"-l {urls} "
                    f"-severity {severity} "
                    f"-jsonl "
                    f"-rate-limit 30 "
                    f"-timeout 5 "
                    f"-retries 1 "
                    f"-o {urls_json}"
                ),
                outfile=str(
                    vuln /
                    "nuclei_urls.log"
                ),
                timeout=900,
            )


            artifacts.extend(
                [
                    str(urls_json),
                    str(
                        vuln /
                        "nuclei_urls.log"
                    ),
                ]
            )


        _merge_files(
            [
                hosts_json,
                urls_json,
            ],
            all_json,
        )


        analysis = _analyse_findings(
            all_json
        )


        findings_file.write_text(
            "\n".join(
                analysis["templates"]
            ),
            encoding="utf-8",
        )


        summary_file.write_text(
            json.dumps(
                analysis,
                indent=4,
            ),
            encoding="utf-8",
        )


        artifacts.extend(
            [
                str(all_json),
                str(findings_file),
                str(summary_file),
            ]
        )


        return ExecutionResult.success_result(
            tool=self.name,
            capability="vulnerability_scanning",
            artifacts=artifacts,
            metadata={
                "severity_profile": severity,
                "finding_count": analysis["finding_count"],
                "severity": analysis["severity"],
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


    stage(
        "STAGE 3 — VULNERABILITY ASSESSMENT",
        "red",
    )


    result = NucleiTool().run(
        ctx
    )


    _print_tool_result(
        result
    )


    ctx.setdefault(
        "tool_results",
        [],
    ).append(
        result
    )


    ok(
        "Stage 3 vulnerability assessment finished ✅"
    )


    return result



###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiTool",
    "stage3_vuln",
]
