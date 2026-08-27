"""
ScopeForgeX
Stage 3 — Vulnerability Assessment
==================================

Provides the canonical Stage 3 vulnerability-assessment adapter:

- Nuclei

The adapter executes Nuclei against pipeline-generated hosts and URLs,
preserves raw outputs and logs, and returns the canonical ExecutionResult.

v1.1.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _quote(
    value: str,
) -> str:
    """
    Safely quote a shell argument.
    """

    import shlex

    return shlex.quote(
        value
    )


def _safe_exists(
    path: Path,
) -> bool:
    """
    Return True when a path exists and contains data.
    """

    return (
        path.exists()
        and path.is_file()
        and path.stat().st_size > 0
    )


def _dedupe_file(
    path: Path,
) -> int:
    """
    Deduplicate non-empty lines in a file.

    Returns:
        Number of unique non-empty lines.
    """

    if not path.exists():
        return 0

    lines = []

    for line in path.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines():

        value = line.strip()

        if value:
            lines.append(
                value
            )

    unique = list(
        dict.fromkeys(
            lines
        )
    )

    path.write_text(
        (
            "\n".join(
                unique
            )
            + "\n"
            if unique
            else ""
        ),
        encoding="utf-8",
    )

    return len(
        unique
    )


def _merge_results(
    inputs: list[Path],
    output: Path,
) -> int:
    """
    Merge multiple Nuclei result files into one deduplicated file.

    Returns:
        Number of unique findings.
    """

    findings: list[str] = []

    for path in inputs:

        if not path.exists():
            continue

        for line in path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():

            value = line.strip()

            if value:
                findings.append(
                    value
                )

    unique = list(
        dict.fromkeys(
            findings
        )
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        (
            "\n".join(
                unique
            )
            + "\n"
            if unique
            else ""
        ),
        encoding="utf-8",
    )

    return len(
        unique
    )


def _input_file(
    ctx: dict[str, Any],
    key: str,
) -> Path | None:
    """
    Resolve a pipeline input file from the execution context.
    """

    pipeline = ctx.get(
        "pipeline",
        {}
    )

    value = pipeline.get(
        key
    )

    if not value:
        return None

    return Path(
        str(value)
    )


def _build_flags(
    options: dict[str, Any],
) -> str:
    """
    Build Nuclei command-line options from normalized tool options.
    """

    flags: list[str] = []

    severity = options.get(
        "severity"
    )

    if severity:

        if isinstance(
            severity,
            (tuple, list),
        ):
            severity_value = ",".join(
                str(value)
                for value in severity
            )

        else:
            severity_value = str(
                severity
            )

        flags.extend(
            [
                "-severity",
                _quote(
                    severity_value
                ),
            ]
        )

    tags = options.get(
        "tags"
    )

    if tags:

        if isinstance(
            tags,
            (tuple, list),
        ):
            tag_value = ",".join(
                str(value)
                for value in tags
            )

        else:
            tag_value = str(
                tags
            )

        flags.extend(
            [
                "-tags",
                _quote(
                    tag_value
                ),
            ]
        )

    templates = options.get(
        "templates"
    )

    if templates:

        if isinstance(
            templates,
            (tuple, list),
        ):
            for template in templates:
                flags.extend(
                    [
                        "-t",
                        _quote(
                            str(template)
                        ),
                    ]
                )

        else:
            flags.extend(
                [
                    "-t",
                    _quote(
                        str(templates)
                    ),
                ]
            )

    rate_limit = options.get(
        "rate_limit"
    )

    if rate_limit is not None:

        flags.extend(
            [
                "-rate-limit",
                str(
                    rate_limit
                ),
            ]
        )

    concurrency = options.get(
        "concurrency"
    )

    if concurrency is not None:

        flags.extend(
            [
                "-c",
                str(
                    concurrency
                ),
            ]
        )

    timeout = options.get(
        "timeout"
    )

    if timeout is not None:

        flags.extend(
            [
                "-timeout",
                str(
                    timeout
                ),
            ]
        )

    retries = options.get(
        "retries"
    )

    if retries is not None:

        flags.extend(
            [
                "-retries",
                str(
                    retries
                ),
            ]
        )

    return " ".join(
        flags
    )


###############################################################################
# Nuclei
###############################################################################


class NucleiTool(
    ToolBase
):
    """
    Template-based vulnerability and security-configuration assessment.
    """

    name = "nuclei"
    display_name = "Nuclei"

    description = (
        "Broad template-based vulnerability and "
        "security-configuration assessment."
    )

    capability = (
        "broad_vulnerability_detection"
    )

    input_type = (
        "host_or_url_list"
    )

    output_type = (
        "vulnerability_findings"
    )

    finding_types = (
        "VULNERABILITY",
        "MISCONFIGURATION",
        "EXPOSED_RESOURCE",
        "CVE",
        "SECURITY_ISSUE",
    )

    risk = "medium"

    supported_options = (
        "severity",
        "tags",
        "templates",
        "rate_limit",
        "concurrency",
        "timeout",
        "retries",
    )

    default_options = {
        "severity": (
            "high",
            "critical",
        ),
        "rate_limit": 30,
        "timeout": 5,
        "retries": 1,
    }

    ###########################################################################
    # Command Construction
    ###########################################################################

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build a Nuclei command from the supplied execution context.

        The context may provide:

        - input_file
        - output_file
        - options
        """

        input_file = ctx.get(
            "input_file"
        )

        output_file = ctx.get(
            "output_file"
        )

        if not input_file:
            raise ValueError(
                "Nuclei requires an input_file."
            )

        if not output_file:
            raise ValueError(
                "Nuclei requires an output_file."
            )

        options = dict(
            self.default_options
        )

        options.update(
            ctx.get(
                "options",
                {}
            )
        )

        flags = _build_flags(
            options
        )

        return (
            "nuclei "
            f"-l {_quote(str(input_file))} "
            f"{flags} "
            f"-o {_quote(str(output_file))}"
        ).strip()

    ###########################################################################
    # Execution
    ###########################################################################

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute Nuclei against pipeline-generated hosts and URLs.
        """

        if not is_tool_installed(
            "nuclei"
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="nuclei not installed",
            )

        outdir = Path(
            str(
                ctx["outdir"]
            )
        )

        vuln_dir = (
            outdir
            / "vuln"
        )

        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        hosts_final = _input_file(
            ctx,
            "hosts_final",
        )

        urls_final = _input_file(
            ctx,
            "urls_final",
        )

        out_hosts = (
            vuln_dir
            / "nuclei_hosts.txt"
        )

        out_urls = (
            vuln_dir
            / "nuclei_urls.txt"
        )

        out_combined = (
            vuln_dir
            / "nuclei.txt"
        )

        log_hosts = (
            vuln_dir
            / "nuclei_hosts.log"
        )

        log_urls = (
            vuln_dir
            / "nuclei_urls.log"
        )

        host_result: ExecutionResult | None = None
        url_result: ExecutionResult | None = None

        #######################################################################
        # Host Scan
        #######################################################################

        if hosts_final and _safe_exists(
            hosts_final
        ):

            host_context = dict(
                ctx
            )

            host_context.update(
                {
                    "input_file": hosts_final,
                    "output_file": out_hosts,
                }
            )

            host_command = self.build_command(
                host_context
            )

            host_result = run_command(
                tool=self.name,
                capability=self.capability,
                cmd=host_command,
                outfile=str(
                    log_hosts
                ),
                timeout=600,
            )

        else:

            out_hosts.write_text(
                "",
                encoding="utf-8",
            )

        #######################################################################
        # URL Scan
        #######################################################################

        if urls_final and _safe_exists(
            urls_final
        ):

            url_context = dict(
                ctx
            )

            url_context.update(
                {
                    "input_file": urls_final,
                    "output_file": out_urls,
                }
            )

            url_command = self.build_command(
                url_context
            )

            url_result = run_command(
                tool=self.name,
                capability=self.capability,
                cmd=url_command,
                outfile=str(
                    log_urls
                ),
                timeout=600,
            )

        else:

            out_urls.write_text(
                "",
                encoding="utf-8",
            )

        #######################################################################
        # Normalize Results
        #######################################################################

        host_count = _dedupe_file(
            out_hosts
        )

        url_count = _dedupe_file(
            out_urls
        )

        total = _merge_results(
            [
                out_hosts,
                out_urls,
            ],
            out_combined,
        )

        #######################################################################
        # Execution Status
        #######################################################################

        executed = (
            host_result is not None
            or url_result is not None
        )

        failed = False

        if host_result is not None:
            failed = (
                failed
                or not host_result.success
            )

        if url_result is not None:
            failed = (
                failed
                or not url_result.success
            )

        if not executed:

            result = ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=(
                    "No valid hosts_final or "
                    "urls_final input was available."
                ),
            )

        elif failed:

            result = ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=(
                    "One or more Nuclei scans failed."
                ),
            )

        else:

            result = ExecutionResult.success_result(
                tool=self.name,
                capability=self.capability,
            )

        #######################################################################
        # Artifacts
        #######################################################################

        artifacts = [
            out_combined,
            out_hosts,
            out_urls,
        ]

        if log_hosts.exists():
            artifacts.append(
                log_hosts
            )

        if log_urls.exists():
            artifacts.append(
                log_urls
            )

        for artifact in artifacts:
            result.add_artifact(
                artifact
            )

        #######################################################################
        # Metadata
        #######################################################################

        result.metadata.update(
            {
                "hosts_scanned": (
                    host_result is not None
                ),
                "urls_scanned": (
                    url_result is not None
                ),
                "host_findings": host_count,
                "url_findings": url_count,
                "total_findings": total,
                "hosts_input": (
                    str(hosts_final)
                    if hosts_final
                    else None
                ),
                "urls_input": (
                    str(urls_final)
                    if urls_final
                    else None
                ),
            }
        )

        return result

    ###########################################################################
    # Output Collection
    ###########################################################################

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Return the canonical execution result.

        Nuclei output remains available through the registered artifacts.
        """

        return result


###############################################################################
# Registry Export
###############################################################################


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiTool",
    "ALL_STAGE3_VULN_TOOLS",
]
