"""
ScopeForgeX
Stage 3 — Vulnerability Assessment
==================================

Provides the canonical Stage 3 vulnerability-assessment adapters:

- Nuclei
- Nikto
- testssl.sh

The adapters execute vulnerability-assessment tools against pipeline-generated
hosts and URLs, preserve raw outputs and logs, and return the canonical
ExecutionResult.

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
    +-- execution delegation
    +-- artifact preservation
    |
    v
ExecutionResult
    |
    v
Collector / Finding Pipeline

The workflow engine must never construct tool-specific commands.

Command construction belongs to the individual tool adapter.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Mapping

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolContext,
    ToolDefinition,
    ToolOption,
)
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


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


def _build_testssl_flags(
    options: Mapping[str, Any],
) -> list[str]:
    """
    Build testssl.sh command-line arguments.
    """

    flags: list[str] = []

    connect_timeout = options.get(
        "connect_timeout"
    )

    if connect_timeout is not None:
        flags.extend(
            [
                "--connect-timeout",
                str(connect_timeout),
            ]
        )

    openssl_timeout = options.get(
        "openssl_timeout"
    )

    if openssl_timeout is not None:
        flags.extend(
            [
                "--openssl-timeout",
                str(openssl_timeout),
            ]
        )

    return flags


###############################################################################
# Nuclei
###############################################################################


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

    def build_arguments(self) -> list[str]:
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

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute Nuclei against ToolContext.input_data.
        """

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="nuclei not installed",
            )

        if not self.context.input_data:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="No Nuclei input targets available.",
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
            / "nuclei_output.txt"
        )

        log_file = (
            vuln_dir
            / "nuclei.log"
        )

        try:
            command = self.build_command()

        except (
            TypeError,
            ValueError,
        ) as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=shlex.join(command),
            outfile=str(log_file),
            timeout=600,
        )

        if output_file.exists():
            result.add_artifact(
                output_file
            )

        if log_file.exists():
            result.add_artifact(
                log_file
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
                "command": command,
            }
        )

        return result

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Preserve the canonical execution result."""

        return result


###############################################################################
# Nikto
###############################################################################


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

    def build_arguments(self) -> list[str]:
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

    def run(
        self,
    ) -> ExecutionResult:
        """Execute Nikto against the supplied target."""

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="nikto not installed",
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
            / "nikto.txt"
        )

        log_file = (
            vuln_dir
            / "nikto.log"
        )

        try:
            command = self.build_command()

        except (
            TypeError,
            ValueError,
        ) as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=shlex.join(command),
            outfile=str(log_file),
            timeout=600,
        )

        if log_file.exists():
            output_file.write_text(
                log_file.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ),
                encoding="utf-8",
            )
        else:
            output_file.write_text(
                "",
                encoding="utf-8",
            )

        result.add_artifact(
            output_file
        )

        if log_file.exists():
            result.add_artifact(
                log_file
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
                "command": command,
            }
        )

        return result

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Preserve the canonical execution result."""

        return result


###############################################################################
# testssl.sh
###############################################################################


class TestSSLTool(
    ToolAdapter
):
    """
    TLS/SSL security-assessment adapter.

    testssl.sh execution is delegated to the ScopeForgeX execution layer.
    Structured parsing is handled by TestSSLCollector.
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
                description="TCP connection timeout in seconds.",
                option_type="integer",
                default=10,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="openssl_timeout",
                flag="--openssl-timeout",
                description="OpenSSL operation timeout in seconds.",
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

        options = _resolve_option_values(
            self
        )

        for option_name in (
            "connect_timeout",
            "openssl_timeout",
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
                    f"testssl.sh {option_name} must be an integer."
                ) from exc

            if integer_value <= 0:
                raise ValueError(
                    f"testssl.sh {option_name} must be greater than zero."
                )

    def build_arguments(self) -> list[str]:
        """Build testssl.sh command arguments."""

        if not self.context.target:
            raise ValueError(
                "testssl.sh requires a target."
            )

        self.validate_options()

        options = _resolve_option_values(
            self
        )

        arguments = _build_testssl_flags(
            options
        )

        arguments.append(
            self.context.target
        )

        return arguments

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute testssl.sh and preserve raw assessment artifacts.

        Structured parsing remains the responsibility of TestSSLCollector.
        """

        from scopeforgex.collectors.testssl import (
            TestSSLCollector,
        )

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="testssl.sh not installed",
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

        try:
            command = self.build_command()

        except (
            TypeError,
            ValueError,
        ) as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        # run_command() expects the command in its shell-string form.
        # Command construction remains argv-oriented at the adapter boundary.
        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=shlex.join(command),
            outfile=str(log_file),
            timeout=900,
        )

        stdout = getattr(
            result,
            "stdout",
            "",
        )

        if isinstance(
            stdout,
            str,
        ):
            output = stdout

        else:
            output = str(
                stdout or ""
            )

        # The runner's outfile contains the combined preserved process output
        # used as the canonical raw testssl.sh artifact when available.
        if log_file.exists() and log_file.stat().st_size > 0:
            output_file.write_text(
                log_file.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ),
                encoding="utf-8",
            )

        else:
            output_file.write_text(
                output,
                encoding="utf-8",
            )

        result.add_artifact(
            output_file
        )

        if log_file.exists():
            result.add_artifact(
                log_file
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
                f"testssl.sh collection failed: {exc}"
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
                "command": command,
            }
        )

        return result

    def collect(
        self,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """Preserve the canonical execution result."""

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

