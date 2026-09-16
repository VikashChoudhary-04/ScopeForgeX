"""
ScopeForgeX
Stage 3 — Vulnerability Assessment
==================================

Provides the canonical Stage 3 vulnerability-assessment adapters:

- Wapiti
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


def _remove_stale_artifact(
    path: Path,
) -> None:
    """
    Remove an artifact from a previous execution.

    This prevents failed or timed-out executions from exposing stale
    assessment data as though it belonged to the current run.
    """

    try:
        if path.exists():
            path.unlink()
    except OSError:
        # Artifact cleanup must never prevent the actual tool execution.
        pass


def _execution_timeout(
    context: ToolContext,
    default: int,
) -> int:
    """
    Resolve the process execution timeout for a custom adapter run.

    Tool-specific timeout options remain responsible for the underlying
    tool's own request/operation timeouts. This value controls the outer
    ScopeForgeX process timeout.

    The value is read from the ToolContext options when supplied so custom
    adapter implementations do not silently ignore workflow-level timeout
    configuration.
    """

    configured = context.options.get(
        "tool_timeout"
    )

    if configured is None:
        configured = context.options.get(
            "process_timeout"
        )

    if configured is None:
        return default

    try:
        timeout = int(
            configured
        )
    except (
        TypeError,
        ValueError,
    ):
        return default

    if timeout <= 0:
        return default

    return timeout


def _is_tls_target(
    target: str,
) -> bool:
    """
    Determine whether a target is applicable to TLS/SSL assessment.

    Explicit HTTP URLs are not TLS targets and must be skipped rather than
    passed to testssl.sh as failed TLS assessments.

    Explicit HTTPS URLs are TLS targets.

    Bare host and host:port values remain eligible because testssl.sh accepts
    host-oriented targets and those values may represent TLS services without
    an explicit URL scheme.

    Args:
        target:
            Target value supplied through ToolContext.

    Returns:
        True when testssl.sh should be executed.
    """

    value = str(
        target or ""
    ).strip()

    if not value:
        return False

    normalized = value.lower()

    if normalized.startswith(
        "https://"
    ):
        return True

    if normalized.startswith(
        "http://"
    ):
        return False

    # A non-HTTP scheme is not a web URL that this adapter can safely
    # interpret as a TLS target. Bare host and host:port values are retained
    # as valid testssl.sh inputs.
    if "://" in normalized:
        return False

    return True


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

    flags: list[str] = [
        "--warnings",
        "batch",
    ]

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
# Wapiti
###############################################################################


class WapitiTool(
    ToolAdapter
):
    """
    Bounded web-application vulnerability and security-configuration
    assessment using Wapiti's native scan-time controls.
    """

    definition = ToolDefinition(
        name="wapiti",
        capability="web_application_vulnerability_detection",
        phase="vulnerability_assessment",
        purpose=(
            "Bounded web-application security assessment with native "
            "scan-time and attack-time controls."
        ),
        executable="wapiti",
        input_type="url",
        output_type="vulnerability_findings",
        finding_types=(
            "VULNERABILITY",
            "MISCONFIGURATION",
            "SECURITY_ISSUE",
        ),
        dependencies=(
            "wapiti",
        ),
        options=(
            ToolOption(
                name="scope",
                flag="--scope",
                description="Wapiti crawl scope.",
                option_type="string",
                default="domain",
                choices=(
                    "url",
                    "page",
                    "folder",
                    "subdomain",
                    "domain",
                    "punk",
                ),
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="max_links_per_page",
                flag="--max-links-per-page",
                description="Maximum links followed per page.",
                option_type="integer",
                default=100,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="max_files_per_dir",
                flag="--max-files-per-dir",
                description="Maximum files tested per directory.",
                option_type="integer",
                default=50,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="max_scan_time",
                flag="--max-scan-time",
                description="Maximum total Wapiti scan time in seconds.",
                option_type="integer",
                default=540,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="max_attack_time",
                flag="--max-attack-time",
                description="Maximum Wapiti attack phase time in seconds.",
                option_type="integer",
                default=480,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="max_parameters",
                flag="--max-parameters",
                description="Maximum parameters accepted per URL/form.",
                option_type="integer",
                default=50,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="timeout",
                flag="-t",
                description="Wapiti HTTP request timeout.",
                option_type="integer",
                default=10,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="format",
                flag="-f",
                description="Wapiti report format.",
                option_type="string",
                default="json",
                choices=(
                    "json",
                    "html",
                    "md",
                    "csv",
                ),
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
        """Validate Wapiti options."""

        super().validate_options()

        options = _resolve_option_values(self)

        for option_name in (
            "max_links_per_page",
            "max_files_per_dir",
            "max_scan_time",
            "max_attack_time",
            "max_parameters",
            "timeout",
        ):
            value = options.get(option_name)

            if value is None:
                continue

            try:
                integer_value = int(value)
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    f"Wapiti {option_name} must be an integer."
                ) from exc

            if integer_value <= 0:
                raise ValueError(
                    f"Wapiti {option_name} must be greater than zero."
                )

        scan_time = int(options["max_scan_time"])
        attack_time = int(options["max_attack_time"])

        if attack_time > scan_time:
            raise ValueError(
                "Wapiti max_attack_time cannot exceed max_scan_time."
            )

    def build_arguments(
        self,
    ) -> list[str]:
        """
        Build Wapiti command-line arguments.

        Wapiti receives the canonical URL target. The native scan and attack
        budgets deliberately remain below the outer ScopeForgeX process
        timeout.
        """

        self.validate_options()

        target = str(
            self.context.target
        ).strip()

        if not target:
            raise ValueError(
                "Wapiti requires a target URL."
            )

        # ScopeForgeX accepts canonical web targets such as bare hostnames
        # and host:port values. Wapiti requires an explicit HTTP(S) URL.
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"

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
            / "wapiti_report.json"
        )

        options = _resolve_option_values(self)

        return [
            "-u",
            target,
            "--scope",
            str(options["scope"]),
            "--max-links-per-page",
            str(options["max_links_per_page"]),
            "--max-files-per-dir",
            str(options["max_files_per_dir"]),
            "--max-scan-time",
            str(options["max_scan_time"]),
            "--max-attack-time",
            str(options["max_attack_time"]),
            "--max-parameters",
            str(options["max_parameters"]),
            "-t",
            str(options["timeout"]),
            "-f",
            "json",
            "-o",
            str(output_file),
        ]

    def run(
        self,
    ) -> ExecutionResult:
        """Execute Wapiti and preserve its JSON report and log."""

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="wapiti not installed",
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
            / "wapiti_report.json"
        )

        log_file = (
            vuln_dir
            / "wapiti.log"
        )

        _remove_stale_artifact(
            output_file
        )
        _remove_stale_artifact(
            log_file
        )

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=_execution_timeout(
                self.context,
                600,
            ),
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
                "target": self.context.target,
                "output_file": str(output_file),
                "log_file": str(log_file),
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

        _remove_stale_artifact(
            output_file
        )
        _remove_stale_artifact(
            log_file
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
            cmd=command,
            outfile=str(log_file),
            timeout=_execution_timeout(
                self.context,
                600,
            ),
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

        _remove_stale_artifact(
            output_file
        )
        _remove_stale_artifact(
            log_file
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
            cmd=command,
            outfile=str(log_file),
            timeout=_execution_timeout(
                self.context,
                600,
            ),
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

    def build_arguments(
        self,
    ) -> list[str]:
        """Build testssl.sh command-line arguments."""

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

        target = str(
            self.context.target or ""
        ).strip()

        if not target:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="testssl.sh requires a target.",
            )

        if not _is_tls_target(
            target
        ):
            return ExecutionResult.skipped(
                tool=self.name,
                capability=self.capability,
                reason=(
                    "TLS assessment not applicable: "
                    f"target '{target}' is an HTTP target."
                ),
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

        _remove_stale_artifact(
            output_file
        )
        _remove_stale_artifact(
            log_file
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
            cmd=command,
            outfile=str(log_file),
            timeout=_execution_timeout(
                self.context,
                900,
            ),
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
    WapitiTool,
    NucleiTool,
    NiktoTool,
    TestSSLTool,
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "WapitiTool",
    "NucleiTool",
    "NiktoTool",
    "TestSSLTool",
    "ALL_STAGE3_VULN_TOOLS",
]

