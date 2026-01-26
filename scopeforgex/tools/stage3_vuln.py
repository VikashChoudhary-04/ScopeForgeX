import os
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


class NucleiTool(ToolBase):
    name = "nuclei"
    stage = 3
    description = "FAST: nuclei scans subhunt subdomains + their endpoints"
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

        # FAST defaults
        base = "-severity high,critical -rate-limit 30 -timeout 5 -retries 1"

        # Scan alive subdomains
        if hosts_final and os.path.exists(hosts_final) and os.path.getsize(hosts_final) > 0:
            run_cmd(f"nuclei -l {hosts_final} {base} -o {out_hosts}", outfile=log_hosts, timeout=600)
        else:
            # If pipeline is empty, don't scan root domain (your requested behavior)
            open(out_hosts, "w", encoding="utf-8").close()

        # Scan endpoints from those subdomains
        if urls_final and os.path.exists(urls_final) and os.path.getsize(urls_final) > 0:
            run_cmd(f"nuclei -l {urls_final} {base} -o {out_urls}", outfile=log_urls, timeout=600)
        else:
            open(out_urls, "w", encoding="utf-8").close()

        # Merge results
        combined = []
        for fp in [out_hosts, out_urls]:
            if os.path.exists(fp):
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    combined += [x.strip() for x in f.readlines() if x.strip()]

        combined = list(dict.fromkeys(combined))
        with open(out_combined, "w", encoding="utf-8") as f:
            f.write("\n".join(combined) + ("\n" if combined else ""))

        return ToolResult(
            self.name,
            True,
            [out_combined, out_hosts, out_urls, log_hosts, log_urls],
            "Nuclei executed on Subhunt pipeline (hosts_final + urls_final)."
        )


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]
