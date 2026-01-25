import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.merger import merge_targets


class Sublist3rTool(ToolBase):
    name = "sublist3r"
    stage = 1
    description = "Enumerate subdomains using Sublist3r (logs saved)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_txt = os.path.join(recon_dir, "sublist3r.txt")
        out_log = os.path.join(recon_dir, "sublist3r.log")

        if not is_tool_installed("sublist3r"):
            return ToolResult(self.name, False, [], "sublist3r not installed")

        # ✅ Capture stdout+stderr into log file
        run_cmd(f"sublist3r -d {ctx['target']} -o {out_txt}", outfile=out_log)

        notes = "Completed (check log if results are empty)."
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes = "Sublist3r finished but output is empty (blocked sources / crash). Check sublist3r.log."

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class DnsreconTool(ToolBase):
    name = "dnsrecon"
    stage = 1
    description = "DNS reconnaissance"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_log = os.path.join(recon_dir, "dnsrecon.log")

        if not is_tool_installed("dnsrecon"):
            return ToolResult(self.name, False, [], "dnsrecon not installed")

        run_cmd(f"dnsrecon -d {ctx['target']} -t std", outfile=out_log)

        return ToolResult(self.name, True, [out_log], "DNS recon saved to dnsrecon.log")


class HttpxAliveTool(ToolBase):
    name = "httpx"
    stage = 1
    description = "Alive web hosts check"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        inp = os.path.join(recon_dir, "sublist3r.txt")
        out_txt = os.path.join(recon_dir, "alive.txt")
        out_log = os.path.join(recon_dir, "httpx.log")

        if not is_tool_installed("httpx"):
            return ToolResult(self.name, False, [], "httpx not installed")

        if not os.path.exists(inp) or os.path.getsize(inp) == 0:
            return ToolResult(self.name, False, [], "sublist3r.txt missing or empty")

        run_cmd(f"cat {inp} | httpx -silent > {out_txt}", outfile=out_log)

        notes = "Alive hosts saved."
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes = "httpx finished but no alive hosts found OR target list was invalid."

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class SubhuntTool(ToolBase):
    name = "subhunt"
    stage = 1
    description = "Expand recon using Subhunt"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        inp = os.path.join(recon_dir, "alive.txt")
        out_txt = os.path.join(recon_dir, "subhunt.txt")
        out_log = os.path.join(recon_dir, "subhunt.log")

        if not is_tool_installed("subhunt"):
            return ToolResult(self.name, False, [], "subhunt not installed")

        if not os.path.exists(inp) or os.path.getsize(inp) == 0:
            return ToolResult(self.name, False, [], "alive.txt missing or empty (httpx produced nothing)")

        run_cmd(f"subhunt -l {inp} -o {out_txt}", outfile=out_log)

        notes = "Subhunt results saved."
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes = "Subhunt ran but produced no results. Check subhunt.log."

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class GauTool(ToolBase):
    name = "gau"
    stage = 1
    description = "Fetch historical URLs using gau"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_txt = os.path.join(recon_dir, "gau.txt")
        out_log = os.path.join(recon_dir, "gau.log")

        if not is_tool_installed("gau"):
            return ToolResult(self.name, False, [], "gau not installed")

        run_cmd(f"gau {ctx['target']} > {out_txt}", outfile=out_log)

        notes = "gau output saved."
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes = "gau produced no URLs (normal for some targets)."

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class KatanaTool(ToolBase):
    name = "katana"
    stage = 1
    description = "Crawl endpoints using katana"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_txt = os.path.join(recon_dir, "katana.txt")
        out_log = os.path.join(recon_dir, "katana.log")

        if not is_tool_installed("katana"):
            return ToolResult(self.name, False, [], "katana not installed")

        run_cmd(f"katana -u https://{ctx['target']} -silent > {out_txt}", outfile=out_log)

        notes = "katana output saved."
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes = "katana produced no endpoints or was blocked. Check katana.log."

        return ToolResult(self.name, True, [out_txt, out_log], notes)


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
        notes = f"{total} unique targets merged into final_targets.txt"
        if total == 0:
            notes = "final_targets.txt is empty (upstream recon produced no valid targets)."

        return ToolResult(self.name, True, [final_targets], notes)


ALL_STAGE1_WEB_TOOLS = [
    Sublist3rTool(),
    DnsreconTool(),
    HttpxAliveTool(),
    SubhuntTool(),
    GauTool(),
    KatanaTool(),
    FinalTargetsTool(),
]
