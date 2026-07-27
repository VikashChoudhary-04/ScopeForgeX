"""
ScopeForgeX v0.5.0
Stage 2 - Network Enumeration Tools

Network service enumeration implementations.

Tools:
    • enum4linux-ng
    • snmpwalk
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _enum_dir(
    ctx: dict,
) -> Path:
    """
    Return the enumeration output directory.
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


def _tool_missing(
    tool_name: str,
) -> ExecutionResult | None:
    """
    Return an ExecutionResult if the required executable is unavailable.
    """

    if is_tool_installed(
        tool_name
    ):
        return None

    return ExecutionResult.failure(
        tool=tool_name,
        capability="network_enumeration",
        error=f"{tool_name} not installed",
    )


###############################################################################
# Enum4Linux-ng
###############################################################################


class Enum4LinuxTool(ToolBase):

    name = "enum4linux-ng"
    stage = 2
    description = "SMB enumeration"
    risk = "medium"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        missing = _tool_missing(
            self.name
        )

        if missing:
            return missing

        outfile = (
            _enum_dir(ctx)
            /
            "enum4linux-ng.txt"
        )

        return run_command(
            tool=self.name,
            capability="smb_enumeration",
            cmd=(
                f"enum4linux-ng "
                f"-A {ctx['target']}"
            ),
            outfile=str(outfile),
        )


###############################################################################
# SNMP Walk
###############################################################################


class SnmpWalkTool(ToolBase):

    name = "snmpwalk"
    stage = 2
    description = "SNMP walk"
    risk = "medium"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        missing = _tool_missing(
            self.name
        )

        if missing:
            return missing

        outfile = (
            _enum_dir(ctx)
            /
            "snmpwalk.txt"
        )

        return run_command(
            tool=self.name,
            capability="snmp_enumeration",
            cmd=(
                f"snmpwalk "
                f"-c public "
                f"-v2c "
                f"{ctx['target']}"
            ),
            outfile=str(outfile),
        )


###############################################################################
# Tool Registration
###############################################################################


ALL_STAGE2_NET_ENUM_TOOLS = [
    Enum4LinuxTool(),
    SnmpWalkTool(),
]


__all__ = [
    "Enum4LinuxTool",
    "SnmpWalkTool",
    "ALL_STAGE2_NET_ENUM_TOOLS",
]
