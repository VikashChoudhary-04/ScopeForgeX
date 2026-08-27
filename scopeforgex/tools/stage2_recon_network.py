"""
ScopeForgeX Network Enumeration Tools
=====================================

Capability-oriented network enumeration adapters.

Integrated capabilities:
    - SMB enumeration
    - SNMP enumeration

The adapters own tool-specific command construction.
The execution layer owns external command execution.

v1.1.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.runtime.enums import AssessmentPhase


###############################################################################
# Helpers
###############################################################################


def _enum_dir(
    ctx: dict[str, Any],
) -> Path:
    """
    Return the network enumeration output directory.
    """

    directory = (
        Path(ctx["outdir"])
        / "enum"
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
    Safely quote a shell argument.
    """

    return shlex.quote(
        value
    )


def _target(
    ctx: dict[str, Any],
) -> str:
    """
    Return the normalized network target.
    """

    target = str(
        ctx.get(
            "target",
            "",
        )
    ).strip()

    if not target:
        raise ValueError(
            "No network target supplied."
        )

    return target


def _tool_missing(
    tool_name: str,
    capability: str,
) -> ExecutionResult | None:
    """
    Return a failure result when a required executable is unavailable.
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
# Enum4Linux-ng
###############################################################################


class Enum4LinuxTool(ToolBase):
    """
    Enumerate SMB services and related Windows network information.
    """

    name = "enum4linux-ng"

    display_name = "enum4linux-ng"

    description = (
        "SMB enumeration."
    )

    phase = AssessmentPhase.ENUMERATION

    capability = "smb_enumeration"

    input_type = "host"

    output_type = "smb_enumeration"

    finding_types = (
        "SMB_SHARE",
        "SMB_USER",
        "SMB_GROUP",
        "SMB_DOMAIN",
        "SMB_CONFIGURATION",
    )

    risk = "medium"

    enabled_by_default = True

    supported_options = ()

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the enum4linux-ng enumeration command.
        """

        target = _target(
            ctx
        )

        return (
            "enum4linux-ng "
            f"-A {_quote(target)}"
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute SMB enumeration through the canonical execution layer.
        """

        capability = self.capability

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

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

        enum_dir = _enum_dir(
            ctx
        )

        output = (
            enum_dir
            / "enum4linux-ng.txt"
        )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=command,
            outfile=str(output),
            timeout=600,
        )

        result.add_artifact(
            output
        )

        result.metadata.update(
            {
                "target": _target(ctx),
            }
        )

        return result


###############################################################################
# SNMP Walk
###############################################################################


class SnmpWalkTool(ToolBase):
    """
    Perform an authorized SNMP walk against a network target.
    """

    name = "snmpwalk"

    display_name = "snmpwalk"

    description = (
        "SNMP walk enumeration."
    )

    phase = AssessmentPhase.ENUMERATION

    capability = "snmp_enumeration"

    input_type = "host"

    output_type = "snmp_enumeration"

    finding_types = (
        "SNMP_OID",
        "SNMP_CONFIGURATION",
        "SNMP_INFORMATION",
    )

    risk = "medium"

    enabled_by_default = True

    supported_options = (
        "community",
        "version",
    )

    default_options = {
        "community": "public",
        "version": "2c",
    }

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the snmpwalk enumeration command.
        """

        options = self.validate_options(
            ctx.get(
                "tool_options",
                {},
            ).get(
                self.name,
                {},
            )
            if isinstance(
                ctx.get(
                    "tool_options",
                    {},
                ),
                dict,
            )
            else {}
        )

        target = _target(
            ctx
        )

        community = str(
            options["community"]
        )

        version = str(
            options["version"]
        )

        return (
            "snmpwalk "
            f"-c {_quote(community)} "
            f"-v {_quote(version)} "
            f"{_quote(target)}"
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute SNMP enumeration through the canonical execution layer.
        """

        capability = self.capability

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

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

        enum_dir = _enum_dir(
            ctx
        )

        output = (
            enum_dir
            / "snmpwalk.txt"
        )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=command,
            outfile=str(output),
            timeout=600,
        )

        result.add_artifact(
            output
        )

        result.metadata.update(
            {
                "target": _target(ctx),
            }
        )

        return result


###############################################################################
# Stage 2 Network Enumeration Compatibility Export
###############################################################################


ALL_STAGE2_NET_ENUM_TOOLS = (
    Enum4LinuxTool(),
    SnmpWalkTool(),
)


###############################################################################
# Public API
###############################################################################


__all__ = [
    "Enum4LinuxTool",
    "SnmpWalkTool",
    "ALL_STAGE2_NET_ENUM_TOOLS",
]
