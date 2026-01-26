import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log


class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "Nuclei scan on pipeline hosts + endpoints"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        vuln_dir = os.path.join(ctx["outdir"], "vuln")

        out_hosts = os.path.join(vuln_dir, "nuclei_hosts.txt")
        out_urls = os.path.join(vuln_dir, "nuclei_urls.txt")
        out_combined = os.path.join(vuln_dir, "nuclei.txt")

        log_hosts = os.path.join(vuln_dir, "nuclei_hosts.log")
        log_urls = os.path.join(vuln_dir, "nuclei_urls.log")

        if not is_tool_installed("nuclei"):
            return ToolResult(self.name, False, [], "nuclei not installed")

        pipe = ctx.get("pipeline", {})
        hosts_final = pipe.get("hosts_final")
        urls_final = pipe.get("urls_final")

        profile = ctx.get("profile", "full_safe")

        # FAST mode = strict limits
        if profile == "fast":
            base = "-severity high,critical -rate-limit 30 -timeout 5 -retries 1"
            max_timeout = 600
        else:
            base = ""
            max_timeout = 1800

        # 1) Scan hosts list
        if hosts_final and os.path.exists(hosts_final) and os.path.getsize(hosts_final) > 0:
            run_cmd(f"nuclei -l {hosts_final} {base} -o {out_hosts}", outfile=log_hosts, timeout=max_timeout)
        else:
            run_cmd(f"nuclei -u https://{ctx['target']} {base} -o {out_hosts}", outfile=log_hosts, timeout=max_timeout)

        # 2) Scan endpoints list
        if urls_final and os.path.exists(urls_final) and os.path.getsize(urls_final) > 0:
            run_cmd(f"nuclei -l {urls_final} {base} -o {out_urls}", outfile=log_urls, timeout=max_timeout)
        else:
            # No endpoints -> leave file empty
            open(out_urls, "w", encoding="utf-8").close()

        # Merge results
        combined_lines = []
        for fp in [out_hosts, out_urls]:
            if os.path.exists(fp):
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    combined_lines += [x.strip() for x in f.readlines() if x.strip()]

        combined_lines = list(dict.fromkeys(combined_lines))  # dedupe preserve order
        with open(out_combined, "w", encoding="utf-8") as f:
            f.write("\n".join(combined_lines) + ("\n" if combined_lines else ""))

        notes = "Nuclei completed (hosts + urls)."
        notes += " | " + build_notes_from_log(log_hosts, "Hosts scan").replace("Completed.", "")
        notes += " | " + build_notes_from_log(log_urls, "URL scan").replace("Completed.", "")

        return ToolResult(
            self.name,
            True,
            [out_combined, out_hosts, out_urls, log_hosts, log_urls],
            notes.strip()
        )


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]
