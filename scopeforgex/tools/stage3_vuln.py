import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed

class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "Automated vulnerability hints"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        recon_dir = os.path.join(ctx["outdir"], "recon")
        out = os.path.join(vuln_dir, "nuclei.txt")

        if not is_tool_installed("nuclei"):
            return ToolResult(self.name, False, [], "nuclei not installed")

        final_targets = os.path.join(recon_dir, "final_targets.txt")
        if os.path.exists(final_targets):
            run_cmd(f"nuclei -l {final_targets} -o {out}")
        else:
            run_cmd(f"nuclei -u https://{ctx['target']} -o {out}")

        return ToolResult(self.name, True, [out])

class NiktoTool(ToolBase):
    name = "nikto"
    stage = 3
    description = "Web server scanner"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "vuln", "nikto.txt")
        if not is_tool_installed("nikto"):
            return ToolResult(self.name, False, [], "nikto not installed")
        run_cmd(f"nikto -h https://{ctx['target']} > {out}")
        return ToolResult(self.name, True, [out])

class WpScanTool(ToolBase):
    name = "wpscan"
    stage = 3
    description = "WordPress scanning"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        out = os.path.join(ctx["outdir"], "vuln", "wpscan.txt")
        if not is_tool_installed("wpscan"):
            return ToolResult(self.name, False, [], "wpscan not installed")
        run_cmd(f"wpscan --url https://{ctx['target']} --enumerate vp,vt,u > {out}")
        return ToolResult(self.name, True, [out])

ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
    NiktoTool(),
    WpScanTool(),
]
