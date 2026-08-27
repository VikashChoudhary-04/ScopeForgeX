"""
ScopeForgeX Network Reconnaissance Tools
========================================

Capability-oriented network reconnaissance adapters.

Integrated capabilities:
    - Network service discovery
    - Deterministic DNS inspection

Integrated tools:
    - Nmap
    - dig

Architecture
------------
Tool adapters own:

    - tool metadata
    - option handling
    - command construction
    - execution delegation
    - artifact collection

The workflow engine must not construct tool-specific commands.

Nmap is the primary network discovery tool.

Naabu and RustScan are intentionally not integrated into the final
ScopeForgeX architecture because their primary port-discovery capability
overlaps with Nmap.

Assessment-phase classification is owned by the canonical tool registry.
Legacy ``stage`` metadata is intentionally not used.

v1.2.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _recon_dir(
    ctx: dict[str, Any],
) -> Path:
    """
    Return the reconnaissance output directory.
    """

    directory = (
        Path(ctx["outdir"])
        / "recon"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _quote(
    value: str,
) -> str:
    """
    Safely quote a command argument.
    """

    return shlex.quote(
        value
    )


def _empty_file(
    path: str | Path,
) -> None:
    """
    Create or truncate a file.
    """

    output = Path(
        path
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        "",
        encoding="utf-8",
    )


def _dedupe_file(
    path: str | Path,
) -> int:
    """
    Remove duplicate non-empty lines while preserving order.

    Returns:
        Number of unique entries.
    """

    output = Path(
        path
    )

    if not output.exists():
        return 0

    try:
        with output.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as infile:

            lines = [
                line.strip()
                for line in infile
                if line.strip()
            ]

        unique = list(
            dict.fromkeys(
                lines
            )
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as outfile:

            if unique:
                outfile.write(
                    "\n".join(unique)
                    + "\n"
                )

    except OSError:
        return 0

    return len(unique)


def _network_only(
    ctx: dict[str, Any],
) -> bool:
    """
    Return True when the current target is a network target.
    """

    return (
        ctx.get("target_type")
        == "network"
    )


def _tool_missing(
    tool_name: str,
    capability: str,
) -> ExecutionResult | None:
    """
    Return a failure result when an executable is unavailable.
    """

    if is_tool_installed(
        tool_name
    ):
        return None

    return ExecutionResult.failure(
        tool=tool_name,
        capability=capability,
        error=f"{tool_name} not installed",
    )


###############################################################################
# Nmap
###############################################################################


class NmapTool(ToolBase):
    """
    Perform network service discovery with Nmap.
    """

    name = "nmap"
    display_name = "Nmap"

    description = (
        "Port discovery, service detection, version detection and "
        "NSE-based network security checks."
    )

    purpose = (
        "Port discovery, service detection, version detection and "
        "NSE-based network security checks."
    )

    capability = (
        "network_service_discovery"
    )

    input_type = "host"
    output_type = "network_scan"

    finding_types = (
        "OPEN_PORT",
        "SERVICE",
        "SERVICE_VERSION",
        "NETWORK_CONFIGURATION",
        "NSE_SECURITY_FINDING",
    )

    risk = "medium"

    supported_options = (
        "ports",
        "service_detection",
        "os_detection",
        "timing",
        "nse_profile",
    )

    default_options = {
        "service_detection": True,
        "os_detection": False,
        "timing": "T3",
        "nse_profile": "safe",
    }

    def _resolve_options(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Resolve Nmap options from the execution context.
        """

        configured = ctx.get(
            "tool_options",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        options = configured.get(
            self.name,
            {},
        )

        if not isinstance(
            options,
            dict,
        ):
            options = {}

        return self.validate_options(
            options
        )

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the Nmap command from structured options.

        The workflow supplies configuration; this adapter owns the
        translation into Nmap command-line arguments.
        """

        target = str(
            ctx.get(
                "target",
                "",
            )
        ).strip()

        if not target:
            raise ValueError(
                "Nmap requires a target host."
            )

        options = self._resolve_options(
            ctx
        )

        command = [
            "nmap",
            "-Pn",
        ]

        ports = options.get(
            "ports"
        )

        if ports:
            command.extend(
                [
                    "-p",
                    str(ports),
                ]
            )

        if options.get(
            "service_detection",
            False,
        ):
            command.append(
                "-sV"
            )

        if options.get(
            "os_detection",
            False,
        ):
            command.append(
                "-O"
            )

        timing = options.get(
            "timing"
        )

        if timing:
            timing_value = str(
                timing
            )

            if not timing_value.startswith(
                "-T"
            ):
                timing_value = (
                    f"-T{timing_value}"
                )

            command.append(
                timing_value
            )

        nse_profile = options.get(
            "nse_profile"
        )

        if nse_profile:

            profile = str(
                nse_profile
            ).lower()

            if profile == "safe":
                command.extend(
                    [
                        "--script",
                        "safe",
                    ]
                )

            elif profile == "default":
                command.append(
                    "-sC"
                )

            elif profile == "none":
                pass

            else:
                command.extend(
                    [
                        "--script",
                        profile,
                    ]
                )

        command.append(
            target
        )

        return " ".join(
            _quote(part)
            for part in command
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute Nmap network reconnaissance.
        """

        capability = self.capability

        if not _network_only(
            ctx
        ):

            return ExecutionResult.skipped(
                tool=self.name,
                capability=capability,
                reason="Skipped (not network target)",
            )

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

        recon_dir = _recon_dir(
            ctx
        )

        log = (
            recon_dir
            / "nmap.log"
        )

        xml = (
            recon_dir
            / "nmap.xml"
        )

        _empty_file(
            xml
        )

        try:
            command = self.build_command(
                ctx
            )
        except ValueError as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=str(exc),
            )

        command = (
            f"{command} "
            f"-oX {_quote(str(xml))}"
        )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=command,
            outfile=str(log),
            timeout=1800,
        )

        result.add_artifact(
            log
        )

        result.add_artifact(
            xml
        )

        result.metadata.update(
            {
                "target": str(
                    ctx.get(
                        "target",
                        "",
                    )
                ),
                "xml_output": str(
                    xml
                ),
            }
        )

        return result


###############################################################################
# dig
###############################################################################


class DigTool(ToolBase):
    """
    Perform deterministic DNS record inspection with dig.
    """

    name = "dig"
    display_name = "dig"

    description = (
        "Deterministic DNS record inspection for A, AAAA, CNAME, MX, "
        "NS, TXT and SOA records."
    )

    purpose = (
        "Deterministic DNS record inspection."
    )

    capability = (
        "dns_record_inspection"
    )

    input_type = "domain"
    output_type = "dns_records"

    finding_types = (
        "DNS_RECORD",
        "DNS_CONFIGURATION",
    )

    risk = "low"

    supported_options = (
        "record_types",
        "short",
    )

    default_options = {
        "record_types": (
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "NS",
            "TXT",
            "SOA",
        ),
        "short": False,
    }

    def _resolve_options(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Resolve dig options from the execution context.
        """

        configured = ctx.get(
            "tool_options",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        options = configured.get(
            self.name,
            {},
        )

        if not isinstance(
            options,
            dict,
        ):
            options = {}

        return self.validate_options(
            options
        )

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build a deterministic dig command.

        One dig invocation is generated per requested record type so that
        the resulting raw evidence clearly identifies the DNS query being
        performed.
        """

        target = str(
            ctx.get(
                "target",
                "",
            )
        ).strip()

        if not target:
            raise ValueError(
                "dig requires a target domain."
            )

        options = self._resolve_options(
            ctx
        )

        record_types = options.get(
            "record_types",
            self.default_options[
                "record_types"
            ],
        )

        if isinstance(
            record_types,
            str,
        ):
            record_types = (
                record_types,
            )

        if not record_types:
            raise ValueError(
                "dig requires at least one DNS record type."
            )

        commands = []

        for record_type in record_types:

            query_type = str(
                record_type
            ).upper()

            command = [
                "dig",
                target,
                query_type,
            ]

            if options.get(
                "short",
                False,
            ):
                command.append(
                    "+short"
                )

            commands.append(
                " ".join(
                    _quote(part)
                    for part in command
                )
            )

        return " && ".join(
            commands
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute deterministic DNS inspection.
        """

        capability = self.capability

        if not _network_only(
            ctx
        ):

            return ExecutionResult.skipped(
                tool=self.name,
                capability=capability,
                reason="Skipped (not network target)",
            )

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

        target = str(
            ctx.get(
                "target",
                "",
            )
        ).strip()

        if not target:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error="dig requires a target domain.",
            )

        recon_dir = _recon_dir(
            ctx
        )

        output = (
            recon_dir
            / "dig.txt"
        )

        log = (
            recon_dir
            / "dig.log"
        )

        _empty_file(
            output
        )

        try:
            command = self.build_command(
                ctx
            )
        except ValueError as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=(
                f"{command} "
                f"> {_quote(str(output))}"
            ),
            outfile=str(log),
            timeout=300,
        )

        result.add_artifact(
            output
        )

        result.add_artifact(
            log
        )

        record_count = _dedupe_file(
            output
        )

        result.metadata.update(
            {
                "target": target,
                "output_file": str(
                    output
                ),
                "records": record_count,
            }
        )

        return result


###############################################################################
# Registry Export
###############################################################################


ALL_STAGE1_NET_TOOLS = [
    NmapTool(),
    DigTool(),
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "NmapTool",
    "DigTool",
    "ALL_STAGE1_NET_TOOLS",
]
