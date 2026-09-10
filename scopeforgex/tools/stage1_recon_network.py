"""
ScopeForgeX Network Reconnaissance Tools
========================================

Canonical network reconnaissance adapters for ScopeForgeX 3.0.

Tools:
    - Amass
    - Nmap
    - Dig

The adapters are responsible for:

    - Tool-specific option validation
    - Command construction
    - Tool execution through the shared execution layer
    - Raw artifact registration
    - Network-target normalization

The execution layer remains responsible for process execution semantics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.models import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolContext,
    ToolDefinition,
    ToolOption,
)
from scopeforgex.runner import run_command


###############################################################################
# Helpers
###############################################################################


def _normalize_target(target: str) -> str:
    """
    Normalize a network target for command construction.

    URL schemes are removed where appropriate while preserving:
        - hostname
        - IPv4 address
        - IPv6 address
        - optional port
    """
    value = str(target or "").strip()

    if not value:
        return ""

    for scheme in (
        "http://",
        "https://",
        "tcp://",
        "udp://",
    ):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
            break

    value = value.split("/", 1)[0]

    if value.startswith("[") and "]" in value:
        host = value[1:value.index("]")]
        remainder = value[value.index("]") + 1:]

        if remainder.startswith(":"):
            return f"{host}{remainder}"

        return host

    return value


def _target_host(target: str) -> str:
    """
    Extract the host portion from a normalized target.
    """
    value = _normalize_target(target)

    if not value:
        return ""

    if value.startswith("[") and "]" in value:
        return value[1:value.index("]")]

    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)

        if port.isdigit():
            return host

    return value


def _target_port(target: str) -> int | None:
    """
    Extract an explicit target port when one is present.
    """
    value = _normalize_target(target)

    if not value:
        return None

    if value.startswith("[") and "]" in value:
        remainder = value[value.index("]") + 1:]

        if remainder.startswith(":") and remainder[1:].isdigit():
            return int(remainder[1:])

        return None

    if value.count(":") == 1:
        _, port = value.rsplit(":", 1)

        if port.isdigit():
            return int(port)

    return None


def _execution_timeout(
    context: ToolContext,
    default: int,
) -> int:
    """
    Resolve a tool execution timeout from the context.
    """
    options = getattr(
        context,
        "options",
        {},
    ) or {}

    value = options.get(
        "timeout",
        default,
    )

    try:
        timeout = int(value)

    except (
        TypeError,
        ValueError,
    ):
        timeout = default

    return max(
        timeout,
        1,
    )


def _artifact_path(
    context: ToolContext,
    tool_name: str,
    filename: str,
) -> Path:
    """
    Construct the raw artifact path for a network reconnaissance tool.
    """
    base = Path(
        context.output_dir
    )

    tool_dir = (
        base
        / "recon"
        / tool_name.lower()
    )

    tool_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    return tool_dir / filename


def _register_artifact(
    result: ExecutionResult,
    path: Path,
) -> None:
    """
    Register an artifact on an execution result.
    """
    path_value = str(path)

    if path_value not in result.artifacts:
        result.artifacts.append(
            path_value
        )


def _record_execution_summary(
    result: ExecutionResult,
) -> dict[str, Any]:
    """
    Convert an individual execution result into a non-recursive summary.

    ExecutionResult objects must never be stored inside another
    ExecutionResult.metadata structure.

    This summary preserves useful per-record execution information without
    embedding another ExecutionResult object or duplicating stdout/stderr.
    """
    metadata = dict(
        result.metadata or {}
    )

    return {
        "record_type": metadata.get(
            "record_type"
        ),
        "success": bool(
            result.success
        ),
        "status": result.status,
        "duration": result.duration,
        "output_file": metadata.get(
            "output_file"
        ),
        "command": metadata.get(
            "command"
        ),
        "artifacts": list(
            result.artifacts
        ),
        "warnings": list(
            result.warnings
        ),
        "errors": list(
            result.errors
        ),
    }


def _normalize_nmap_timing(value: Any) -> str | None:
    """
    Normalize a configured Nmap timing template.

    The profile may express timing as either:
        - 3
        - 4
        - "3"
        - "4"
        - "T3"
        - "T4"

    Nmap's canonical command-line form is:
        -T3
        -T4
    """
    if value in (
        None,
        "",
        False,
    ):
        return None

    text = str(value).strip().upper()

    if text.startswith("-T"):
        text = text[2:]

    elif text.startswith("T"):
        text = text[1:]

    if text not in {
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
    }:
        raise ValueError(
            f"Invalid Nmap timing template: {value!r}. "
            "Expected T0 through T5."
        )

    return f"-T{text}"


###############################################################################
# Amass
###############################################################################


class AmassTool(ToolAdapter):
    """
    Amass network reconnaissance adapter.
    """

    definition = ToolDefinition(
        name="amass",
        capability="attack_surface_discovery",
        phase="reconnaissance",
        purpose=(
            "Passive and active attack-surface discovery using Amass."
        ),
        executable="amass",
        input_type="domain",
        output_type="raw",
        finding_types=(
            "SUBDOMAIN",
        ),
        dependencies=(
            "amass",
        ),
        options=(
            ToolOption(
                name="active",
                flag="-active",
                description=(
                    "Enable active Amass enumeration."
                ),
                option_type="boolean",
                default=False,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="passive",
                flag="-passive",
                description=(
                    "Enable passive Amass enumeration."
                ),
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="bruteforce",
                flag="-brute",
                description=(
                    "Enable Amass DNS brute-force enumeration."
                ),
                option_type="boolean",
                default=False,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="wordlist",
                flag="-w",
                description=(
                    "Wordlist used for active Amass enumeration."
                ),
                option_type="path",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="timeout",
                flag="--timeout",
                description="Amass execution timeout.",
                option_type="integer",
                default=300,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    def build_arguments(self) -> list[str]:
        """
        Build Amass-specific command-line arguments.
        """
        self.validate_options()

        target = _target_host(
            self.context.target
        )

        if not target:
            raise ValueError(
                "Amass requires a network target."
            )

        arguments = [
            "enum",
            "-d",
            target,
        ]

        active = bool(
            self.get_option(
                "active"
            )
        )

        passive = bool(
            self.get_option(
                "passive"
            )
        )

        bruteforce = bool(
            self.get_option(
                "bruteforce"
            )
        )

        wordlist = self.get_option(
            "wordlist"
        )

        if active:
            arguments.append(
                "-active"
            )

        if passive:
            arguments.append(
                "-passive"
            )

        if bruteforce:
            arguments.append(
                "-brute"
            )

        if wordlist:
            if not bruteforce:
                arguments.append(
                    "-brute"
                )

            arguments.extend(
                [
                    "-w",
                    str(wordlist),
                ]
            )

        return arguments


###############################################################################
# Nmap
###############################################################################


class NmapTool(ToolAdapter):
    """
    Nmap network service discovery adapter.
    """

    definition = ToolDefinition(
        name="nmap",
        capability="network_service_discovery",
        phase="reconnaissance",
        purpose=(
            "Network port and service discovery using Nmap."
        ),
        executable="nmap",
        input_type="host",
        output_type="raw",
        finding_types=(
            "OPEN_PORT",
            "SERVICE",
            "SERVICE_VERSION",
        ),
        dependencies=(
            "nmap",
        ),
        options=(
            ToolOption(
                name="nse_profile",
                flag="--script",
                description=(
                    "Nmap NSE script profile to execute."
                ),
                option_type="string",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="os_detection",
                flag="-O",
                description=(
                    "Enable Nmap operating-system detection."
                ),
                option_type="boolean",
                default=False,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="service_detection",
                flag="-sV",
                description=(
                    "Enable Nmap service/version detection."
                ),
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="timing",
                flag="-T",
                description=(
                    "Nmap timing template."
                ),
                option_type="string",
                default="T3",
                choices=(
                    "T0",
                    "T1",
                    "T2",
                    "T3",
                    "T4",
                    "T5",
                    "0",
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                ),
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="top_ports",
                flag="--top-ports",
                description=(
                    "Scan the specified number of most common ports."
                ),
                option_type="integer",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="timeout",
                flag="--timeout",
                description="Nmap execution timeout.",
                option_type="integer",
                default=300,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    def build_arguments(self) -> list[str]:
        """
        Build Nmap-specific command-line arguments.

        When the original ScopeForgeX target contains an explicit port,
        that port is preserved and passed to Nmap with ``-p``. This prevents
        a target such as ``http://127.0.0.1:3000`` from being reduced to only
        the host and accidentally causing Nmap to scan its default port set.

        ``timing`` accepts both ``T4`` and ``4`` style profile values but is
        normalized to Nmap's canonical ``-T4`` form.
        """
        self.validate_options()

        target = _target_host(
            self.context.target
        )

        if not target:
            raise ValueError(
                "Nmap requires a network target."
            )

        arguments: list[str] = []

        service_detection = self.get_option(
            "service_detection"
        )

        if service_detection:
            arguments.append(
                "-sV"
            )

        os_detection = self.get_option(
            "os_detection"
        )

        if os_detection:
            arguments.append(
                "-O"
            )

        timing = _normalize_nmap_timing(
            self.get_option(
                "timing"
            )
        )

        if timing:
            arguments.append(
                timing
            )

        nse_profile = self.get_option(
            "nse_profile"
        )

        if nse_profile:
            profile = str(
                nse_profile
            ).strip()

            if profile:
                arguments.extend(
                    [
                        "--script",
                        profile,
                    ]
                )

        explicit_port = _target_port(
            self.context.target
        )

        top_ports = self.get_option(
            "top_ports"
        )

        if explicit_port is not None:
            arguments.extend(
                [
                    "-p",
                    str(explicit_port),
                ]
            )

        elif top_ports:
            arguments.extend(
                [
                    "--top-ports",
                    str(top_ports),
                ]
            )

        arguments.append(
            target
        )

        return arguments


###############################################################################
# Dig
###############################################################################


class DigTool(ToolAdapter):
    """
    DNS reconnaissance adapter.

    Dig is executed separately for each configured record type. The first
    execution result remains the canonical ExecutionResult while all
    individual record executions are represented through compact,
    non-recursive metadata summaries.

    Raw command output remains available through the generated artifacts.
    """

    definition = ToolDefinition(
        name="dig",
        capability="dns_reconnaissance",
        phase="reconnaissance",
        purpose=(
            "DNS record reconnaissance using dig."
        ),
        executable="dig",
        input_type="host",
        output_type="raw",
        finding_types=(
            "DNS_RECORD",
            "DNS_CONFIGURATION",
        ),
        dependencies=(
            "dig",
        ),
        options=(
            ToolOption(
                name="record_types",
                flag="",
                description=(
                    "DNS record types to query."
                ),
                option_type="list",
                default=(
                    "A",
                    "AAAA",
                    "CNAME",
                    "MX",
                    "NS",
                    "SOA",
                ),
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="timeout",
                flag="--timeout",
                description="Dig execution timeout.",
                option_type="integer",
                default=60,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    DEFAULT_RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "SOA",
    )

    def build_arguments(self) -> list[str]:
        """
        Build the default Dig command arguments.

        Dig uses a custom run() implementation because one ScopeForgeX Dig
        execution intentionally performs multiple DNS record-type queries.
        The returned arguments represent the first/default query and satisfy
        the canonical ToolAdapter command-construction contract.
        """
        self.validate_options()

        target = _target_host(
            self.context.target
        )

        if not target:
            raise ValueError(
                "dig requires a network target."
            )

        record_types = self._record_types()

        return [
            "+noall",
            "+answer",
            target,
            record_types[0],
        ]

    def _record_types(self) -> tuple[str, ...]:
        """
        Resolve configured DNS record types.
        """
        configured_record_types = self.get_option(
            "record_types"
        )

        if not configured_record_types:
            return self.DEFAULT_RECORD_TYPES

        if isinstance(
            configured_record_types,
            str,
        ):
            record_types = tuple(
                item.strip().upper()
                for item in configured_record_types.split(",")
                if item.strip()
            )

        else:
            record_types = tuple(
                str(item).strip().upper()
                for item in configured_record_types
                if str(item).strip()
            )

        return (
            record_types
            if record_types
            else self.DEFAULT_RECORD_TYPES
        )

    def run(self) -> ExecutionResult:
        """
        Execute Dig separately for each configured DNS record type.

        The custom execution path is intentional: a single Dig assessment
        produces multiple raw DNS artifacts and therefore cannot be represented
        by one command without losing the per-record execution boundary.
        """
        self.validate_context()

        target = _target_host(
            self.context.target
        )

        if not target:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="dig requires a network target.",
            )

        record_types = self._record_types()

        timeout = _execution_timeout(
            self.context,
            60,
        )

        results: list[ExecutionResult] = []

        for record_type in record_types:

            command = [
                "dig",
                "+noall",
                "+answer",
                target,
                record_type,
            ]

            output_file = _artifact_path(
                self.context,
                self.name,
                f"{record_type.lower()}.txt",
            )

            result = run_command(
                tool=self.name,
                capability=self.capability,
                cmd=command,
                outfile=str(output_file),
                timeout=timeout,
            )

            result.metadata.update(
                {
                    "target": self.context.target,
                    "network_target": target,
                    "target_port": _target_port(
                        self.context.target
                    ),
                    "record_type": record_type,
                    "output_file": str(output_file),
                    "command": command,
                }
            )

            _register_artifact(
                result,
                output_file,
            )

            results.append(
                result
            )

        if not results:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="No DNS record executions were created.",
            )

        first = results[0]

        if len(results) == 1:
            return first

        # Preserve compact, non-recursive summaries for all per-record
        # executions. Never store ExecutionResult instances here.
        first.metadata[
            "record_results"
        ] = [
            _record_execution_summary(
                result
            )
            for result in results
        ]

        first.metadata[
            "record_result_count"
        ] = len(results)

        return first


###############################################################################
# Public API
###############################################################################


ALL_STAGE1_NETWORK_TOOLS = [
    AmassTool,
    NmapTool,
    DigTool,
]


__all__ = [
    "AmassTool",
    "NmapTool",
    "DigTool",
    "ALL_STAGE1_NETWORK_TOOLS",
]
