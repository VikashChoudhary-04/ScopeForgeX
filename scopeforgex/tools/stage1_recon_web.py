import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.merger import merge_targets

class Sublist3rTool(ToolBase):
    name = "sublist3r"
    stage = 1
    description = "Enumerate subdomains using Sublist3r"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "sublist3r.txt")
        if not is_tool_installed("sublist3r"):
            return ToolResult(self.name, False, [], "sublist3r not installed")
        run_cmd(f"sublist3r -d {ctx['target']} -o {out}")
        return ToolResult(self.name, True, [out])

class DnsreconTool(ToolBase):
    name = "dnsrecon"
    stage = 1
    description = "DNS reconnaissance"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "dnsrecon.txt")
        if not is_tool_installed("dnsrecon"):
            return ToolResult(self.name, False, [], "dnsrecon not installed")
        run_cmd(f"dnsrecon -d {ctx['target']} -t std > {out}")
        return ToolResult(self.name, True, [out])

class HttpxAliveTool(ToolBase):
    name = "httpx"
    stage = 1
    description = "Alive web hosts check"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        inp = os.path.join(recon_dir, "sublist3r.txt")
        out = os.path.join(recon_dir, "alive.txt")
        if not is_tool_installed("httpx"):
            return ToolResult(self.name, False, [], "httpx not installed")
        if not os.path.exists(inp):
            return ToolResult(self.name, False, [], "sublist3r.txt missing")
        run_cmd(f"cat {inp} | httpx -silent > {out}")
        return ToolResult(self.name, True, [out])

class SubhuntTool(ToolBase):
    name = "subhunt"
    stage = 1
    description = "Expand recon using Subhunt"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        inp = os.path.join(recon_dir, "alive.txt")
        out = os.path.join(recon_dir, "subhunt.txt")
        if not is_tool_installed("subhunt"):
            return ToolResult(self.name, False, [], "subhunt not installed")
        if not os.path.exists(inp):
            return ToolResult(self.name, False, [], "alive.txt missing")
        run_cmd(f"subhunt -l {inp} -o {out}")
        return ToolResult(self.name, True, [out])

class GauTool(ToolBase):
    name = "gau"
    stage = 1
    description = "Fetch historical URLs using gau"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "gau.txt")
        if not is_tool_installed("gau"):
            return ToolResult(self.name, False, [], "gau not installed")
        run_cmd(f"gau {ctx['target']} > {out}")
        return ToolResult(self.name, True, [out])

class KatanaTool(ToolBase):
    name = "katana"
    stage = 1
    description = "Crawl endpoints using katana"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "recon", "katana.txt")
        if not is_tool_installed("katana"):
            return ToolResult(self.name, False, [], "katana not installed")
        run_cmd(f"katana -u https://{ctx['target']} -silent > {out}")
        return ToolResult(self.name, True, [out])

class FinalTargetsTool(ToolBase):
    name = "final_targets"
    stage = 1
    description = "Merge recon targets into final_targets.txt"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        sublist = os.path.join(recon_dir, "sublist3r.txt")
        alive = os.path.join(recon_dir, "alive.txt")
        subhunt = os.path.join(recon_dir, "subhunt.txt")
        final_targets = os.path.join(recon_dir, "final_targets.txt")

        total = merge_targets(final_targets, sublist, alive, subhunt)
        return ToolResult(self.name, True, [final_targets], f"{total} unique targets")

ALL_STAGE1_WEB_TOOLS = [
    Sublist3rTool(),
    DnsreconTool(),
    HttpxAliveTool(),
    SubhuntTool(),
    GauTool(),
    KatanaTool(),
    FinalTargetsTool(),
]
