import os
from scopeforgex.ui import stage, ok


def _count_lines(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for line in f if line.strip())


def _read_preview(path: str, limit: int = 20) -> list[str]:
    if not path or not os.path.exists(path):
        return []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()][:limit]


def _existing_files(paths: list[str]) -> list[str]:
    return [path for path in paths if path and os.path.exists(path)]


def stage6_reporting(ctx: dict):
    stage("STAGE 6 — REPORTING", "magenta")

    outdir = ctx.get("outdir", "outputs/unknown")
    report_path = os.path.join(outdir, "report.md")

    pipe = ctx.get("pipeline", {})

    hosts_raw = pipe.get("hosts_raw")
    hosts_alive = pipe.get("hosts_alive")
    hosts_final = pipe.get("hosts_final")
    urls_raw = pipe.get("urls_raw")
    urls_final = pipe.get("urls_final")

    nuclei_txt = os.path.join(outdir, "vuln", "nuclei.txt")
    nuclei_hosts = os.path.join(outdir, "vuln", "nuclei_hosts.txt")
    nuclei_urls = os.path.join(outdir, "vuln", "nuclei_urls.txt")
    nuclei_hosts_log = os.path.join(outdir, "vuln", "nuclei_hosts.log")
    nuclei_urls_log = os.path.join(outdir, "vuln", "nuclei_urls.log")

    raw_count = _count_lines(hosts_raw)
    alive_count = _count_lines(hosts_alive)
    final_count = _count_lines(hosts_final)
    url_count = _count_lines(urls_final)
    nuclei_count = _count_lines(nuclei_txt)

    final_preview = _read_preview(hosts_final, 20)
    nuclei_preview = _read_preview(nuclei_txt, 30)

    generated_files = _existing_files([
        hosts_raw,
        hosts_alive,
        hosts_final,
        urls_raw,
        urls_final,
        nuclei_txt,
        nuclei_hosts,
        nuclei_urls,
        nuclei_hosts_log,
        nuclei_urls_log,
    ])

    md = []

    md.append("# ScopeForgeX Report\n\n")

    md.append("## Assessment Context\n\n")
    md.append(f"- **Target:** `{ctx.get('target', '-')}`\n")
    md.append(f"- **Profile:** `{ctx.get('profile', '-')}`\n")
    md.append(f"- **Target Type:** `{ctx.get('target_type', '-')}`\n\n")

    md.append("## Recon Summary\n\n")
    md.append(f"- Raw hosts discovered: **{raw_count}**\n")
    md.append(f"- Alive hosts identified: **{alive_count}**\n")
    md.append(f"- Final hosts available downstream: **{final_count}**\n")
    md.append(f"- Final URLs discovered: **{url_count}**\n\n")

    md.append("### Final Hosts Preview\n\n")

    if final_preview:
        md.append("```text\n")
        md.extend(f"{host}\n" for host in final_preview)
        md.append("```\n\n")
    else:
        md.append("_No hosts are present in `hosts_final.txt`._\n\n")

    md.append("## Vulnerability Identification\n\n")
    md.append(f"- Nuclei findings recorded: **{nuclei_count}**\n\n")

    if nuclei_preview:
        md.append("### Nuclei Findings Preview\n\n")
        md.append("```text\n")
        md.extend(f"{finding}\n" for finding in nuclei_preview)
        md.append("```\n\n")
    else:
        md.append(
            "_No Nuclei findings were recorded in the combined findings file._\n\n"
        )
        md.append(
            "An empty findings file does not by itself prove that the target "
            "has no vulnerabilities. Review the scan logs for execution errors, "
            "timeouts, filtering, or other limitations.\n\n"
        )

    md.append("## Generated Output Files\n\n")

    if generated_files:
        for path in generated_files:
            md.append(f"- `{path}`\n")
    else:
        md.append("- No tracked pipeline output files were found.\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("".join(md))

    ok(f"Report generated: {report_path}")
