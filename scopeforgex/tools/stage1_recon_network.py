import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


class NaabuTool(ToolBase):
    name = "naabu"
    stage = 1
    description = "Fast port discovery (network targets only)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "network":
            return ToolResult(self.name, False, [], "Skipped (web/domain target)")

        out = os.path.join(ctx["outdir"], "recon", "naabu.log")

        if not is_tool_installed("naabu"):
            return ToolResult(self.name, False, [], "naabu not installed")

        # ✅ safer default: top ports only
        run_cmd(f"naabu -host {ctx['target']} -top-ports 1000 -silent", outfile=out)

        return ToolResult(self.name, True, [out], "naabu scan finished (top 1000 ports)")


class RustscanTool(ToolBase):
    name = "rustscan"
    stage = 1
    description = "Fast port scan (network targets only)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "network":
            return ToolResult(self.name, False, [], "Skipped (web/domain target)")

        out = os.path.join(ctx["outdir"], "recon", "rustscan.log")

        if not is_tool_installed("rustscan"):
            return ToolResult(self.name, False, [], "rustscan not installed")

        # ✅ safer default: top ports only
        run_cmd(f"rustscan -a {ctx['target']} --ulimit 5000 -- -sV", outfile=out)

        return ToolResult(self.name, True, [out], "rustscan finished")


class NmapTool(ToolBase):
    name = "nmap"
    stage = 1
    description = "Nmap service enumeration (network targets only)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "network":
            return ToolResult(self.name, False, [], "Skipped (web/domain target)")

        out = os.path.join(ctx["outdir"], "recon", "nmap.log")

        if not is_tool_installed("nmap"):
            return ToolResult(self.name, False, [], "nmap not installed")

        # ✅ safe basic scan
        run_cmd(f"nmap -Pn -sC -sV {ctx['target']}", outfile=out)

        return ToolResult(self.name, True, [out], "nmap scan finished")


ALL_STAGE1_NET_TOOLS = [
    NaabuTool(),
    RustscanTool(),
    NmapTool(),
]
