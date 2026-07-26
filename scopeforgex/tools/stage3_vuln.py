import os

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


NUCLEI_FAST_FLAGS = (
    "-severity high,critical "
    "-rate-limit 30 "
    "-timeout 5 "
    "-retries 1"
)


def _merge_results(inputs, output):
    """
    Merge multiple nuclei result files into a single deduplicated file.
    """

    findings = []

    for path in inputs:
        if not os.path.exists(path):
            continue

        with open(path, "r", encoding="utf-8", errors="ignore") as infile:
            findings.extend(
                line.strip()
                for line in infile
                if line.strip()
            )

    findings = list(dict.fromkeys(findings))

    with open(output, "w", encoding="utf-8") as outfile:
        if findings:
            outfile.write("\n".join(findings) + "\n")

    return len(findings)


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
            return ToolResult(
                self.name,
                False,
                [],
                "nuclei not installed",
            )

        pipeline = ctx.get("pipeline", {})

        hosts_final = pipeline.get("hosts_final")
        urls_final = pipeline.get("urls_final")

        # Scan alive hosts
        if (
            hosts_final
            and os.path.exists(hosts_final)
            and os.path.getsize(hosts_final) > 0
        ):
            run_cmd(
                f"nuclei -l {hosts_final} "
                f"{NUCLEI_FAST_FLAGS} "
                f"-o {out_hosts}",
                outfile=log_hosts,
                timeout=600,
            )
        else:
            open(out_hosts, "w", encoding="utf-8").close()

        # Scan discovered endpoints
        if (
            urls_final
            and os.path.exists(urls_final)
            and os.path.getsize(urls_final) > 0
        ):
            run_cmd(
                f"nuclei -l {urls_final} "
                f"{NUCLEI_FAST_FLAGS} "
                f"-o {out_urls}",
                outfile=log_urls,
                timeout=600,
            )
        else:
            open(out_urls, "w", encoding="utf-8").close()

        total = _merge_results(
            [out_hosts, out_urls],
            out_combined,
        )

        notes = (
            f"Nuclei executed on hosts_final + urls_final "
            f"({total} unique findings)."
        )

        return ToolResult(
            self.name,
            True,
            [
                out_combined,
                out_hosts,
                out_urls,
                log_hosts,
                log_urls,
            ],
            notes,
        )


ALL_STAGE3_VULN_TOOLS = [
    NucleiTool(),
]
