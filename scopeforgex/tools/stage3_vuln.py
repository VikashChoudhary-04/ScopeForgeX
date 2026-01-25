import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log


class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "Automated vulnerability hints"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        recon_dir = os.path.join(ctx["outdir"], "recon")

        out_txt = os.path.join(vuln_dir, "nuclei.txt")
        out_log = os.path.join(vuln_dir, "nuclei.log")

        if not is_tool_installed("nuclei"):
            return ToolResult(self.name, False, [], "nuclei not installed")

        final_targets = os.path.join(recon_dir, "final_targets.txt")

        if os.path.exists(final_targets) and os.path.getsize(final_targets) > 0:
            run_cmd(f"nuclei -l {final_targets} -o {out_txt}", outfile=out_log)
        else:
            run_cmd(f"nuclei -u https://{ctx['target']} -o {out_txt}", outfile=out_log)

        notes = build_notes_from_log(out_log, "Nuclei finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No findings or blocked/filtered target.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class NiktoTool(ToolBase):
    name = "nikto"
    stage = 3
    description = "Web server scanner"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        out_txt = os.path.join(vuln_dir, "nikto.txt")
        out_log = os.path.join(vuln_dir, "nikto.log")

        if not is_tool_installed("nikto"):
            return ToolResult(self.name, False, [], "nikto not installed")

        run_cmd(f"nikto -h https://{ctx['target']} > {out_txt}", outfile=out_log)

        notes = build_notes_from_log(out_log, "Nikto finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Check nikto.log.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class WpScanTool(ToolBase):
    name = "wpscan"
    stage = 3
    description = "WordPress scanning"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        out_txt = os.path.join(vuln_dir, "wpscan.txt")
        out_log = os.path.join(vuln_dir, "wpscan.log")

        if not is_tool_installed("wpscan"):
            return ToolResult(self.name, False, [], "wpscan not installed")

        # ✅ aggressive enumeration can trigger 403 or 429, so logs matter
        cmd = f"wpscan --url https://{ctx['target']} --enumerate vp,vt,u"
        run_cmd(f"{cmd} > {out_txt}", outfile=out_log)

        notes = build_notes_from_log(out_log, "WPScan finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [Empty output. Possible WAF/403 or target not WordPress.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
    NiktoTool(),
    WpScanTool(),
]
