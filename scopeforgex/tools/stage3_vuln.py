import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log


class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "Nuclei scan using pipeline targets"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")
        out_txt = os.path.join(vuln_dir, "nuclei.txt")
        out_log = os.path.join(vuln_dir, "nuclei.log")

        if not is_tool_installed("nuclei"):
            return ToolResult(self.name, False, [], "nuclei not installed")

        pipe = ctx.get("pipeline", {})
        hosts_final = pipe.get("hosts_final")

        profile = ctx.get("profile", "full_safe")

        if profile == "fast":
            cmd = (
                f"nuclei -u https://{ctx['target']} "
                f"-severity high,critical "
                f"-rate-limit 30 "
                f"-timeout 5 "
                f"-retries 1 "
                f"-o {out_txt}"
            )
            run_cmd(cmd, outfile=out_log, timeout=600)
        else:
            if hosts_final and os.path.exists(hosts_final) and os.path.getsize(hosts_final) > 0:
                cmd = f"nuclei -l {hosts_final} -o {out_txt}"
            else:
                cmd = f"nuclei -u https://{ctx['target']} -o {out_txt}"

            run_cmd(cmd, outfile=out_log, timeout=1800)

        notes = build_notes_from_log(out_log, "Nuclei finished.")
        return ToolResult(self.name, True, [out_txt, out_log], notes)


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]
