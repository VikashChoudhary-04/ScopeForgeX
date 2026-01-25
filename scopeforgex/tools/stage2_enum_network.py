import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed

class Enum4LinuxTool(ToolBase):
    name = "enum4linux-ng"
    stage = 2
    description = "SMB enumeration"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "enum", "enum4linux-ng.txt")
        if not is_tool_installed("enum4linux-ng"):
            return ToolResult(self.name, False, [], "enum4linux-ng not installed")
        run_cmd(f"enum4linux-ng -A {ctx['target']} > {out}")
        return ToolResult(self.name, True, [out])

class SnmpWalkTool(ToolBase):
    name = "snmpwalk"
    stage = 2
    description = "SNMP walk"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "enum", "snmpwalk.txt")
        if not is_tool_installed("snmpwalk"):
            return ToolResult(self.name, False, [], "snmpwalk not installed")
        run_cmd(f"snmpwalk -c public -v2c {ctx['target']} > {out}")
        return ToolResult(self.name, True, [out])

ALL_STAGE2_NET_ENUM_TOOLS = [
    Enum4LinuxTool(),
    SnmpWalkTool(),
]
