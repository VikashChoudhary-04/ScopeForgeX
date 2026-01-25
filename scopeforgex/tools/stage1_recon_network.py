import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed

class NaabuTool(ToolBase):
    name = "naabu"
    stage = 1
    description = "Fast port discovery"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "naabu.txt")
        if not is_tool_installed("naabu"):
            return ToolResult(self.name, False, [], "naabu not installed")
        run_cmd(f"naabu -host {ctx['target']} -silent -o {out}")
        return ToolResult(self.name, True, [out])

class RustscanTool(ToolBase):
    name = "rustscan"
    stage = 1
    description = "Fast port scanner"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "rustscan.txt")
        if not is_tool_installed("rustscan"):
            return ToolResult(self.name, False, [], "rustscan not installed")
        run_cmd(f"rustscan -a {ctx['target']} -- -sV -oN {out}")
        return ToolResult(self.name, True, [out])

class NmapTool(ToolBase):
    name = "nmap"
    stage = 1
    description = "Nmap service enumeration"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "nmap.txt")
        if not is_tool_installed("nmap"):
            return ToolResult(self.name, False, [], "nmap not installed")
        run_cmd(f"nmap -Pn -sC -sV {ctx['target']} -oN {out}")
        return ToolResult(self.name, True, [out])

ALL_STAGE1_NET_TOOLS = [
    NaabuTool(),
    RustscanTool(),
    NmapTool(),
]
