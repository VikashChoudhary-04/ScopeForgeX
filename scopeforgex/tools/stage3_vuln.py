"""
ScopeForgeX
Stage 3 — Vulnerability Assessment
==================================

Provides the canonical Stage 3 vulnerability-assessment adapters:

- Nuclei
- Nikto
- testssl.sh

The adapters construct tool-specific commands and perform post-execution
result collection. Process execution remains the responsibility of the
ScopeForgeX execution layer.

Architecture
------------

Workflow Engine
    |
    v
Tool Registry
    |
    v
ToolAdapter
    |
    +-- ToolDefinition
    +-- ToolContext
    +-- option validation
    +-- command construction
    +-- result collection
    +-- artifact preservation
    |
    v
ToolExecutor
    |
    v
ExecutionResult
    |
    v
Collector / Finding Pipeline

The workflow engine must never construct tool-specific commands.

ToolExecutor owns subprocess execution.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Mapping

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolDefinition,
    ToolOption,
)


###############################################################################
# Helpers
###############################################################################


def _quote(
    value: Any,
) -> str:
    """Safely quote a command argument."""

    return shlex.quote(
        str(value)
    )


def _safe_exists(
    path: Path,
) -> bool:
    """Return True when a path exists and contains data."""

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

    lines: list[str] = []

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
            "\n".join(unique)
            + "\n"
            if unique
            else ""
        ),
        encoding="utf-8",
    )

    return len(unique)


def _merge_results(
    inputs: list[Path],
    output: Path,
) -> int:
    """
    Merge multiple result files into one deduplicated file.

    Returns:
        Number of unique non-empty findings.
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
            "\n".join(unique)
            + "\n"
            if unique
            else ""
        ),
        encoding="utf-8",
    )

    return len(unique)


def _resolve_option_values(
    adapter: ToolAdapter,
) -> dict[str, Any]:
    """
    Return tool defaults merged with explicitly configured ToolContext
    options.
    """

    values = {
        option.name: option.default
        for option in adapter.options
        if option.default is not None
    }

    values.update(
        adapter.context.options
    )

    return values


def _result_stdout(
    result: ExecutionResult,
) -> str:
    """
    Return normalized execution stdout.
    """

    value = getattr(
        result,
        "stdout",
        "",
    )

    if isinstance(
        value,
        bytes,
    ):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(
        value or ""
    )


def _result_stderr(
    result: ExecutionResult,
) -> str:
    """
    Return normalized execution stderr.
    """

    value = getattr(
        result,
        "stderr",
        "",
    )

    if isinstance(
        value,
        bytes,
    ):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(
        value or ""
    )


def _write_text_artifact(
    result: ExecutionResult,
    path: Path,
    content: str,
) -> None:
    """
    Write a deterministic text artifact and attach it to the result.
    """

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
    )

    result.add_artifact(
        path
    )


def _write_execution_log(
    result: ExecutionResult,
    path: Path,
) -> None:
    """
    Preserve raw execution output as a deterministic log artifact.

    stdout is preferred. stderr is appended when present so warnings and
    runtime diagnostics are not silently discarded.
    """

    stdout = _result_stdout(
        result
    )

    stderr = _result_stderr(
        result
    )

    content = stdout

    if stderr:
        if content and not content.endswith("\n"):
            content += "\n"

        content += stderr

    _write_text_artifact(
        result,
        path,
        content,
    )


###############################################################################
# Nuclei
###############################################################################


def _build_nuclei_flags(
    options: Mapping[str, Any],
) -> list[str]:
    """
    Build Nuclei command-line arguments.
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
                severity_value,
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
                tag_value,
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
                        str(template),
                    ]
                )

        else:
            flags.extend(
                [
                    "-t",
                    str(templates),
                ]
            )

    rate_limit = options.get(
        "rate_limit"
    )

    if rate_limit is not None:
        flags.extend(
            [
                "-rate-limit",
                str(rate_limit),
            ]
        )

    concurrency = options.get(
        "concurrency"
    )

    if concurrency is not None:
        flags.extend(
            [
                "-c",
                str(concurrency),
            ]
        )

    timeout = options.get(
        "timeout"
    )

    if timeout is not None:
        flags.extend(
            [
                "-timeout",
                str(timeout),
            ]
        )

    retries = options.get(
        "retries"
    )

    if retries is not None:
        flags.extend(
            [
                "-retries",
                str(retries),
            ]
        )

    return flags


class NucleiTool(
    ToolAdapter
):
    """
    Template-based vulnerability and security-configuration assessment.
    """

    definition = ToolDefinition(
        name="nuclei",
        capability="broad_vulnerability_detection",
        phase="vulnerability_assessment",
        purpose=(
            "Broad infrastructure, service and vulnerability detection "
            "through the Nuclei template ecosystem."
        ),
        executable="nuclei",
        input_type="host_or_url_list",
        output_type="vulnerability_findings",
        finding_types=(
            "VULNERABILITY",
            "MISCONFIGURATION",
            "EXPOSED_RESOURCE",
            "CVE",
            "SECURITY_ISSUE",
        ),
        dependencies=(
            "nuclei",
        ),
        options=(
            ToolOption(
                name="severity",
                flag="-severity",
                description="Nuclei severity levels.",
                option_type="sequence",
                default=(
                    "high",
                    "critical",
                ),
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="tags",
                flag="-tags",
                description="Nuclei template tags.",
                option_type="sequence",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="templates",
                flag="-t",
                description="Nuclei templates.",
                option_type="sequence",
                default=None,
                safe=True,
                aggressive=True,
                repeatable=True,
            ),
            ToolOption(
                name="rate_limit",
                flag="-rate-limit",
                description="Maximum Nuclei requests per second.",
                option_type="integer",
                default=30,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="concurrency",
                flag="-c",
                description="Nuclei concurrency.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="timeout",
                flag="-timeout",
                description="Nuclei request timeout.",
                option_type="integer",
                default=5,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="retries",
                flag="-retries",
                description="Nuclei retry count.",
                option_type="integer",
                default=1,
                safe=True,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(
        self,
    ) -> None:
        """Validate Nuclei options."""

        super().validate_options()

        options = _resolve_option_values(
            self
        )

        severity = options.get(
            "severity"
        )

        if severity is not None and not isinstance(
            severity,
            (str, tuple, list),
        ):
            raise TypeError(
                "Nuclei severity must be a string, tuple or list."
            )

        for option_name in (
            "rate_limit",
            "concurrency",
            "timeout",
            "retries",
        ):
            value = options.get(
                option_name
            )

            if value is None:
                continue

            try:
                integer_value = int(
                    value
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise TypeError(
                    f"Nuclei {option_name} must be an integer."
                ) from exc

            if integer_value <= 0:
                raise ValueError(
                    f"Nuclei {option_name} must be greater than zero."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """
        Build Nuclei command-line arguments.

        ToolContext.input_data is the canonical pipeline input channel.
        """

        self.validate_options()

        targets = [
            str(value).strip()
            for value in self.context.input_data
            if str(value).strip()
        ]

        if not targets:
            raise ValueError(
                "Nuclei requires at least one input target."
            )

        vuln_dir = (
            self.context.output_dir
            / "vuln"
        )

        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        input_file = (
            vuln_dir
            / "nuclei_input.txt"
        )

        output_file = (
            vuln_dir
            / "nuclei_output.txt"
        )

        input_file.write_text(
            "\n".join(targets)
            + "\n",
            encoding="utf-8",
        )

        options = _resolve_option_values(
            self
        )

        arguments = [
            "-l",
            str(input_file),
        ]

        arguments.extend(
            _build_nuclei_flags(
                options
            )
        )

        arguments.extend(
            [
                "-o",
                str(output_file),
            ]
        )

        return arguments

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Preserve Nuclei output artifacts after canonical execution.
        """

        vuln_dir = (
            self.context.output_dir
            / "vuln"
        )

        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        input_file = (
            vuln_dir
            / "nuclei_input.txt"
        )

        output_file = (
            vuln_dir
            / "nuclei_output.txt"
        )

        log_file = (
            vuln_dir
            / "nuclei.log"
        )

        if input_file.exists():
            result.add_artifact(
                input_file
            )

        if output_file.exists():
            result.add_artifact(
                output_file
            )

        _write_execution_log(
            result,
            log_file,
        )

        result.metadata.update(
            {
                "input_targets": len(
                    self.context.input_data
                ),
                "output_file": str(
                    output_file
                ),
                "log_file": str(
                    log_file
                ),
            }
        )

        return result


###############################################################################
# Nikto
###############################################################################


def _build_nikto_flags(
    options: Mapping[str, Any],
) -> list[str]:
    """
    Build Nikto command-line arguments.
    """

    flags: list[str] = []

    tuning = options.get(
        "tuning"
    )

    if tuning:
        flags.extend(
            [
                "-Tuning",
                str(tuning),
            ]
        )

    timeout = options.get(
        "timeout"
    )

    if timeout is not None:
        flags.extend(
            [
                "-timeout",
                str(timeout),
            ]
        )

    return flags


class NiktoTool(
    ToolAdapter
):
    """
    Web-server-specific vulnerability assessment.
    """

    definition = ToolDefinition(
        name="nikto",
        capability="web_server_security_assessment",
        phase="vulnerability_assessment",
        purpose="Web-server-specific security assessment.",
        executable="nikto",
        input_type="url",
        output_type="vulnerability_findings",
        finding_types=(
            "WEB_SERVER_ISSUE",
            "MISCONFIGURATION",
            "EXPOSED_FILE",
            "SERVER_VULNERABILITY",
        ),
        dependencies=(
            "nikto",
        ),
        options=(
            ToolOption(
                name="tuning",
                flag="-Tuning",
                description="Nikto tuning options.",
                option_type="string",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="timeout",
                flag="-timeout",
                description="Nikto timeout.",
                option_type="integer",
                default=10,
                safe=True,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(
        self,
    ) -> None:
        """Validate Nikto options."""

        super().validate_options()

        options = _resolve_option_values(
            self
        )

        timeout = options.get(
            "timeout"
        )

        if timeout is not None:
            try:
                timeout_value = int(
                    timeout
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise TypeError(
                    "Nikto timeout must be an integer."
                ) from exc

            if timeout_value <= 0:
                raise ValueError(
                    "Nikto timeout must be greater than zero."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """Build Nikto command-line arguments."""

        if not self.context.target:
            raise ValueError(
                "Nikto requires a target."
            )

        self.validate_options()

        options = _resolve_option_values(
            self
        )

        arguments = [
            "-h",
            self.context.target,
        ]

        arguments.extend(
            _build_nikto_flags(
                options
            )
        )

        return arguments

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Preserve Nikto raw output and log artifacts after execution.
        """

        vuln_dir = (
            self.context.output_dir
            / "vuln"
        )

        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = (
            vuln_dir
            / "nikto.txt"
        )

        log_file = (
            vuln_dir
            / "nikto.log"
        )

        stdout = _result_stdout(
            result
        )

        stderr = _result_stderr(
            result
        )

        content = stdout

        if stderr:
            if content and not content.endswith("\n"):
                content += "\n"

            content += stderr

        _write_text_artifact(
            result,
            output_file,
            content,
        )

        _write_execution_log(
            result,
            log_file,
        )

        result.metadata.update(
            {
                "target": self.context.target,
                "output_file": str(
                    output_file
                ),
                "log_file": str(
                    log_file
                ),
            }
        )

        return result


###############################################################################
# testssl.sh
###############################################################################


def _testssl_target(
    target: str,
) -> str:
    """
    Return the target in the form accepted by testssl.sh.

    testssl.sh accepts hosts, host:port values and URLs.
    """

    normalized = str(
        target or ""
    ).strip()

    if not normalized:
        raise ValueError(
            "testssl.sh requires a target."
        )

    return normalized


class TestSSLTool(
    ToolAdapter
):
    """
    TLS/SSL security-assessment adapter.

    testssl.sh execution is delegated to the ScopeForgeX execution layer.

    Post-execution artifact preservation and structured parsing are handled
    by collect().
    """

    definition = ToolDefinition(
        name="testssl.sh",
        capability="tls_security_assessment",
        phase="vulnerability_assessment",
        purpose="TLS/SSL security assessment.",
        executable="testssl.sh",
        input_type="host",
        output_type="raw",
        finding_types=(
            "TLS_CONFIGURATION",
            "WEAK_PROTOCOL",
            "WEAK_CIPHER",
            "CERTIFICATE_ISSUE",
            "TLS_VULNERABILITY",
        ),
        dependencies=(
            "testssl.sh",
        ),
        options=(
            ToolOption(
                name="connect_timeout",
                flag="--connect-timeout",
                description=(
                    "Maximum TCP connection timeout in seconds."
                ),
                option_type="integer",
                default=10,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="openssl_timeout",
                flag="--openssl-timeout",
                description=(
                    "Maximum OpenSSL operation timeout in seconds."
                ),
                option_type="integer",
                default=10,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    def validate_options(
        self,
    ) -> None:
        """Validate testssl.sh options."""

        super().validate_options()

        for name in (
            "connect_timeout",
            "openssl_timeout",
        ):
            value = self.get_option(
                name,
                10,
            )

            if (
                not isinstance(
                    value,
                    int,
                )
                or isinstance(
                    value,
                    bool,
                )
            ):
                raise TypeError(
                    f"testssl.sh {name} must be an integer."
                )

            if value <= 0:
                raise ValueError(
                    f"testssl.sh {name} must be greater than zero."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """
        Build testssl.sh command arguments.
        """

        self.validate_options()

        target = _testssl_target(
            self.context.target
        )

        return [
            "--connect-timeout",
            str(
                self.get_option(
                    "connect_timeout",
                    10,
                )
            ),
            "--openssl-timeout",
            str(
                self.get_option(
                    "openssl_timeout",
                    10,
                )
            ),
            target,
        ]

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Preserve testssl.sh raw output and invoke TestSSLCollector.
        """

        from scopeforgex.collectors.testssl import (
            TestSSLCollector,
        )

        vuln_dir = (
            self.context.output_dir
            / "vuln"
        )

        vuln_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = (
            vuln_dir
            / "testssl.txt"
        )

        log_file = (
            vuln_dir
            / "testssl.log"
        )

        stdout = _result_stdout(
            result
        )

        stderr = _result_stderr(
            result
        )

        content = stdout

        if stderr:
            if content and not content.endswith("\n"):
                content += "\n"

            content += stderr

        _write_text_artifact(
            result,
            output_file,
            content,
        )

        _write_execution_log(
            result,
            log_file,
        )

        try:
            collector = TestSSLCollector()

            observations = collector.parse(
                result,
                {
                    "target": self.context.target,
                },
            )

            result.metadata.update(
                {
                    "collector": "TestSSLCollector",
                    "observation_count": len(
                        observations
                    ),
                }
            )

        except Exception as exc:
            result.add_warning(
                (
                    f"testssl.sh collection failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

        result.metadata.update(
            {
                "target": self.context.target,
                "output_file": str(
                    output_file
                ),
                "log_file": str(
                    log_file
                ),
            }
        )

        return result


###############################################################################
# Stage 3 Tool Collection
###############################################################################


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool,
    NiktoTool,
    TestSSLTool,
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiTool",
    "NiktoTool",
    "TestSSLTool",
    "ALL_STAGE3_VULN_TOOLS",
]
