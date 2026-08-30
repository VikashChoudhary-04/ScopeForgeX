"""
ScopeForgeX Network Reconnaissance Tools
========================================

Adapters for network-oriented reconnaissance tools in the frozen
ScopeForgeX core toolset.

Tools
-----

- Amass
- Nmap
- dig

Architecture
------------

Workflow Engine
    |
    v
Tool Registry
    |
    v
Network Recon ToolAdapter
    |
    +-- ToolDefinition
    +-- ToolContext
    +-- option validation
    +-- command construction
    +-- execution delegation
    +-- artifact preservation
    |
    v
Execution Layer
    |
    v
ExecutionResult

The adapters in this module own tool-specific command construction.

They do NOT implement subprocess execution directly.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolDefinition,
    ToolOption,
)
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _recon_directory(
    context,
) -> Path:
    """
    Return the Stage 1 reconnaissance output directory.
    """

    directory = (
        context.output_dir
        / "recon"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _write_stdout_artifact(
    result: ExecutionResult,
    path: Path,
) -> None:
    """
    Preserve command stdout as a deterministic raw-output artifact.
    """

    stdout = getattr(
        result,
        "stdout",
        "",
    )

    if isinstance(
        stdout,
        bytes,
    ):
        stdout = stdout.decode(
            "utf-8",
            errors="replace",
        )

    path.write_text(
        str(stdout or ""),
        encoding="utf-8",
    )


def _add_log_artifact(
    result: ExecutionResult,
    path: Path,
) -> None:
    """
    Add a log artifact when the execution layer created one.
    """

    if path.exists():
        result.add_artifact(
            path
        )


###############################################################################
# Amass
###############################################################################


class AmassTool(
    ToolAdapter
):
    """
    Amass reconnaissance adapter.

    Purpose:
        Broad attack-surface discovery and DNS relationship enumeration.
    """

    definition = ToolDefinition(
        name="amass",
        capability="attack_surface_discovery",
        phase="reconnaissance",
        purpose=(
            "Broad attack-surface discovery, DNS relationships, "
            "subdomains and infrastructure relationships."
        ),
        executable="amass",
        input_type="target",
        output_type="raw",
        finding_types=(
            "SUBDOMAIN",
            "DNS_ASSET",
            "HOST",
        ),
        dependencies=(
            "amass",
        ),
        options=(
            ToolOption(
                name="passive",
                flag="-passive",
                description="Run Amass in passive mode.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="active",
                flag="-active",
                description="Enable active Amass enumeration.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
            ToolOption(
                name="brute",
                flag="-brute",
                description="Enable Amass brute-force enumeration.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
            ToolOption(
                name="timeout",
                flag="-timeout",
                description="Amass enumeration timeout in minutes.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(
        self,
    ) -> None:
        """Validate Amass-specific option types and ranges."""

        super().validate_options()

        for key in (
            "passive",
            "active",
            "brute",
        ):
            if not self.has_option(
                key
            ):
                continue

            value = self.get_option(
                key
            )

            if not isinstance(
                value,
                bool,
            ):
                raise TypeError(
                    f"{key} option for Amass must be boolean."
                )

        if self.has_option(
            "timeout"
        ):
            timeout = self.get_option(
                "timeout"
            )

            if (
                not isinstance(
                    timeout,
                    int,
                )
                or isinstance(
                    timeout,
                    bool,
                )
            ):
                raise TypeError(
                    "Amass timeout must be an integer."
                )

            if timeout <= 0:
                raise ValueError(
                    "Amass timeout must be greater than zero."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """Build Amass-specific command-line arguments."""

        self.validate_options()

        arguments: list[str] = [
            "enum",
        ]

        if self.get_option(
            "passive",
            True,
        ):
            arguments.append(
                "-passive"
            )

        if self.get_option(
            "active",
            False,
        ):
            arguments.append(
                "-active"
            )

        if self.get_option(
            "brute",
            False,
        ):
            arguments.append(
                "-brute"
            )

        timeout = self.get_option(
            "timeout"
        )

        if timeout is not None:
            arguments.extend(
                [
                    "-timeout",
                    str(timeout),
                ]
            )

        arguments.extend(
            [
                "-d",
                self.context.target,
            ]
        )

        return arguments

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute Amass through the ScopeForgeX execution layer.
        """

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="amass not installed",
            )

        recon_dir = _recon_directory(
            self.context
        )

        output_file = (
            recon_dir
            / "amass.txt"
        )

        log_file = (
            recon_dir
            / "amass.log"
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
            timeout=600,
        )

        _write_stdout_artifact(
            result,
            output_file,
        )

        result.add_artifact(
            output_file
        )

        _add_log_artifact(
            result,
            log_file,
        )

        result.metadata.update(
            {
                "target": self.context.target,
                "output_file": str(
                    output_file
                ),
                "command": command,
            }
        )

        return result


###############################################################################
# Nmap
###############################################################################


class NmapTool(
    ToolAdapter
):
    """
    Nmap network reconnaissance adapter.

    Purpose:
        Port discovery, service detection and controlled NSE checks.
    """

    definition = ToolDefinition(
        name="nmap",
        capability="network_service_discovery",
        phase="reconnaissance",
        purpose=(
            "Port discovery, port state, service detection, "
            "version detection and NSE security checks."
        ),
        executable="nmap",
        input_type="host",
        output_type="raw",
        finding_types=(
            "OPEN_PORT",
            "SERVICE",
            "SERVICE_VERSION",
            "NETWORK_CONFIGURATION",
            "NSE_SECURITY_FINDING",
        ),
        dependencies=(
            "nmap",
        ),
        options=(
            ToolOption(
                name="ports",
                flag="-p",
                description="Ports or port ranges to scan.",
                option_type="string",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="service_detection",
                flag="-sV",
                description="Enable service and version detection.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="os_detection",
                flag="-O",
                description="Enable operating system detection.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
            ToolOption(
                name="timing",
                flag="",
                description="Nmap timing template.",
                option_type="string",
                default=None,
                choices=(
                    "T0",
                    "T1",
                    "T2",
                    "T3",
                    "T4",
                    "T5",
                ),
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="nse_profile",
                flag="--script",
                description="NSE script profile.",
                option_type="string",
                default=None,
                choices=(
                    "safe",
                    "default",
                    "none",
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
        """Validate Nmap-specific option types and values."""

        super().validate_options()

        for key in (
            "service_detection",
            "os_detection",
        ):
            if not self.has_option(
                key
            ):
                continue

            value = self.get_option(
                key
            )

            if not isinstance(
                value,
                bool,
            ):
                raise TypeError(
                    f"{key} option for Nmap must be boolean."
                )

        if self.has_option(
            "ports"
        ):
            ports = self.get_option(
                "ports"
            )

            if ports is not None:
                ports = str(
                    ports
                ).strip()

                if not ports:
                    raise ValueError(
                        "Nmap ports cannot be empty."
                    )

        if self.has_option(
            "timing"
        ):
            timing = str(
                self.get_option(
                    "timing"
                )
            )

            if timing not in {
                "T0",
                "T1",
                "T2",
                "T3",
                "T4",
                "T5",
            }:
                raise ValueError(
                    "Nmap timing must be one of T0 through T5."
                )

        if self.has_option(
            "nse_profile"
        ):
            nse_profile = str(
                self.get_option(
                    "nse_profile"
                )
            ).lower()

            if nse_profile not in {
                "safe",
                "default",
                "none",
            }:
                raise ValueError(
                    "Nmap nse_profile must be safe, default or none."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """Build Nmap-specific command-line arguments."""

        self.validate_options()

        arguments: list[str] = []

        ports = self.get_option(
            "ports"
        )

        if ports:
            arguments.extend(
                [
                    "-p",
                    str(ports),
                ]
            )

        if self.get_option(
            "service_detection",
            True,
        ):
            arguments.append(
                "-sV"
            )

        if self.get_option(
            "os_detection",
            False,
        ):
            arguments.append(
                "-O"
            )

        timing = self.get_option(
            "timing"
        )

        if timing:
            arguments.append(
                f"-{timing}"
            )

        nse_profile = self.get_option(
            "nse_profile"
        )

        if nse_profile == "safe":
            arguments.extend(
                [
                    "--script",
                    "safe",
                ]
            )

        elif nse_profile == "default":
            arguments.extend(
                [
                    "--script",
                    "default",
                ]
            )

        arguments.append(
            self.context.target
        )

        return arguments

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute Nmap through the ScopeForgeX execution layer.
        """

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="nmap not installed",
            )

        recon_dir = _recon_directory(
            self.context
        )

        output_file = (
            recon_dir
            / "nmap.txt"
        )

        log_file = (
            recon_dir
            / "nmap.log"
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
            timeout=600,
        )

        _write_stdout_artifact(
            result,
            output_file,
        )

        result.add_artifact(
            output_file
        )

        _add_log_artifact(
            result,
            log_file,
        )

        result.metadata.update(
            {
                "target": self.context.target,
                "output_file": str(
                    output_file
                ),
                "command": command,
            }
        )

        return result


###############################################################################
# dig
###############################################################################


class DigTool(
    ToolAdapter
):
    """
    dig DNS inspection adapter.

    Purpose:
        Deterministic DNS record inspection.
    """

    _DEFAULT_RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
    )

    definition = ToolDefinition(
        name="dig",
        capability="dns_enumeration",
        phase="reconnaissance",
        purpose="Deterministic DNS inspection.",
        executable="dig",
        input_type="domain",
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
                description="DNS record type(s) to query.",
                option_type="sequence",
                default=_DEFAULT_RECORD_TYPES,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    _VALID_RECORD_TYPES = {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
        "CAA",
        "PTR",
        "SRV",
    }

    def _record_types(
        self,
    ) -> tuple[str, ...]:
        """
        Return configured DNS record types, falling back to the adapter
        declaration when the profile does not provide the option.
        """

        record_types = self.get_option(
            "record_types",
            self._DEFAULT_RECORD_TYPES,
        )

        if record_types is None:
            record_types = self._DEFAULT_RECORD_TYPES

        if isinstance(
            record_types,
            str,
        ):
            record_types = (
                record_types,
            )

        if not isinstance(
            record_types,
            (tuple, list),
        ):
            raise TypeError(
                "dig record_types must be a sequence of strings."
            )

        normalized_types: list[str] = []

        for record_type in record_types:
            value = str(
                record_type
            ).strip().upper()

            if value not in self._VALID_RECORD_TYPES:
                raise ValueError(
                    f"Unsupported dig record type: {record_type}"
                )

            normalized_types.append(
                value
            )

        if not normalized_types:
            raise ValueError(
                "dig requires at least one record type."
            )

        return tuple(
            normalized_types
        )

    def validate_options(
        self,
    ) -> None:
        """Validate configured DNS record types."""

        super().validate_options()

        self._record_types()

    def build_arguments(
        self,
    ) -> list[str]:
        """
        Build dig-specific command-line arguments.

        dig accepts one query type per invocation. The adapter therefore uses
        the first configured record type.
        """

        self.validate_options()

        record_types = self._record_types()

        record_type = record_types[0]

        return [
            self.context.target,
            record_type,
        ]

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute dig through the ScopeForgeX execution layer.

        One invocation is performed using the first configured record type.
        """

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="dig not installed",
            )

        recon_dir = _recon_directory(
            self.context
        )

        try:
            record_types = self._record_types()
        except (
            TypeError,
            ValueError,
        ) as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        record_type = str(
            record_types[0]
        ).lower()

        output_file = (
            recon_dir
            / f"dig_{record_type}.txt"
        )

        log_file = (
            recon_dir
            / f"dig_{record_type}.log"
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
            timeout=120,
        )

        _write_stdout_artifact(
            result,
            output_file,
        )

        result.add_artifact(
            output_file
        )

        _add_log_artifact(
            result,
            log_file,
        )

        result.metadata.update(
            {
                "target": self.context.target,
                "record_type": record_type,
                "output_file": str(
                    output_file
                ),
                "command": command,
            }
        )

        return result


###############################################################################
# Public API
###############################################################################


__all__ = [
    "AmassTool",
    "NmapTool",
    "DigTool",
]
