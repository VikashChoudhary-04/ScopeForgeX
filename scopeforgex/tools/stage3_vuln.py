import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log


class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "Automated vulnerability hints (FAST optimized)"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        recon_dir = os.path.join(ctx["outdir"], "recon")

        out_txt = os.path.join(vuln_dir, "nuclei.txt")
        out_log = os.path.join(vuln_dir, "nuclei.log")

        if not is_tool_installed("nuclei"):
            return ToolResult(self.name, False, [], "nuclei not installed")

        profile = ctx.get("profile", "full_safe")
        final_targets = os.path.join(recon_dir, "final_targets.txt")

        # ✅ FAST MODE: keep nuclei short and useful
        if profile == "fast":
            cmd = (
                f"nuclei -u https://{ctx['target']} "
                f"-severity high,critical "
                f"-rate-limit 30 "
                f"-timeout 5 "
                f"-retries 1 "
                f"-o {out_txt}"
            )
            run_cmd(cmd, outfile=out_log, timeout=600)  # max 10 min
        else:
            # FULL_SAFE mode: scan full target list if available
            if os.path.exists(final_targets) and os.path.getsize(final_targets) > 0:
                cmd = f"nuclei -l {final_targets} -o {out_txt}"
            else:
                cmd = f"nuclei -u https://{ctx['target']} -o {out_txt}"

            run_cmd(cmd, outfile=out_log, timeout=1800)  # max 30 min

        notes = build_notes_from_log(out_log, "Nuclei finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No findings or blocked/filtered target.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class NiktoTool(ToolBase):
    name = "nikto"
    stage = 3
    description = "Web server scanner (FULL_SAFE recommended)"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        profile = ctx.get("profile", "full_safe")
        if profile == "fast":
            return ToolResult(self.name, False, [], "Skipped in FAST mode (slow tool)")

        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        out_txt = os.path.join(vuln_dir, "nikto.txt")
        out_log = os.path.join(vuln_dir, "nikto.log")

        if not is_tool_installed("nikto"):
            return ToolResult(self.name, False, [], "nikto not installed")

        run_cmd(f"nikto -h https://{ctx['target']} > {out_txt}", outfile=out_log, timeout=1800)

        notes = build_notes_from_log(out_log, "Nikto finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Check nikto.log.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class WpScanTool(ToolBase):
    name = "wpscan"
    stage = 3
    description = "WordPress scanning (FULL_SAFE recommended)"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        profile = ctx.get("profile", "full_safe")
        if profile == "fast":
            return ToolResult(self.name, False, [], "Skipped in FAST mode (slow/blocked often)")

        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        out_txt = os.path.join(vuln_dir, "wpscan.txt")
        out_log = os.path.join(vuln_dir, "wpscan.log")

        if not is_tool_installed("wpscan"):
            return ToolResult(self.name, False, [], "wpscan not installed")

        cmd = f"wpscan --url https://{ctx['target']} --enumerate vp,vt,u"
        run_cmd(f"{cmd} > {out_txt}", outfile=out_log, timeout=1800)

        notes = build_notes_from_log(out_log, "WPScan finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [Empty output. Possible WAF/403 or target not WordPress.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
    NiktoTool(),
    WpScanTool(),
]
