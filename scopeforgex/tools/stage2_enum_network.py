"""
ScopeForgeX Stage 2 - Network Enumeration Tools
===============================================

Network service enumeration implementations.

Tools:
    • enum4linux-ng
    • snmpwalk

v0.4.0
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


def _enum_dir(ctx: dict) -> Path:
    """
    Return the enumeration output directory.
    """

    directory = Path(ctx["outdir"]) / "enum"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _tool_missing(tool_name: str) -> ToolResult | None:
    """
    Return a ToolResult if the required executable is unavailable.
    """

    if is_tool_installed(tool_name):
        return None

    return ToolResult(
        tool_name,
        False,
        [],
        f"{tool_name} not installed",
    )


class Enum4LinuxTool(ToolBase):

    name = "enum4linux-ng"
    stage = 2
    description = "SMB enumeration"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:

        missing = _tool_missing(self.name)
        if missing:
            return missing

        outfile = _enum_dir(ctx) / "enum4linux-ng.txt"

        run_cmd(
            f"enum4linux-ng -A {ctx['target']}",
            outfile=str(outfile),
        )

        return ToolResult(
            self.name,
            True,
            [str(outfile)],
            "enum4linux-ng completed",
        )


class SnmpWalkTool(ToolBase):

    name = "snmpwalk"
    stage = 2
    description = "SNMP walk"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:

        missing = _tool_missing(self.name)
        if missing:
            return missing

        outfile = _enum_dir(ctx) / "snmpwalk.txt"

        run_cmd(
            f"snmpwalk -c public -v2c {ctx['target']}",
            outfile=str(outfile),
        )

        return ToolResult(
            self.name,
            True,
            [str(outfile)],
            "snmpwalk completed",
        )


ALL_STAGE2_NET_ENUM_TOOLS = [
    Enum4LinuxTool(),
    SnmpWalkTool(),
]
