import os
from scopeforgex.ui import stage, ok


def _count_lines(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return len([x for x in f.readlines() if x.strip()])


def _read_preview(path: str, limit: int = 20) -> list[str]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.readlines() if x.strip()]
    return lines[:limit]


def stage6_reporting(ctx: dict):
    stage("STAGE 6 — REPORTING & CLEANUP", "magenta")

    outdir = ctx.get("outdir", "outputs/unknown")
    report_path = os.path.join(outdir, "report.md")

    pipe = ctx.get("pipeline", {})
    hosts_raw = pipe.get("hosts_raw")
    hosts_alive = pipe.get("hosts_alive")
    hosts_final = pipe.get("hosts_final")

    nuclei_txt = os.path.join(outdir, "vuln", "nuclei.txt")
    nuclei_log = os.path.join(outdir, "vuln", "nuclei.log")

    raw_count = _count_lines(hosts_raw)
    alive_count = _count_lines(hosts_alive)
    final_count = _count_lines(hosts_final)
    nuclei_count = _count_lines(nuclei_txt)

    final_preview = _read_preview(hosts_final, 20)
    nuclei_preview = _read_preview(nuclei_txt, 30)

    md = []
    md.append("# ScopeForgeX Report\n")
    md.append(f"**Target:** {ctx.get('target', '-')}\n")
    md.append(f"**Profile:** {ctx.get('profile', '-')}\n")
    md.append(f"**Target Type:** {ctx.get('target_type', '-')}\n")

    md.append("## Recon Summary\n")
    md.append(f"- Raw hosts discovered: **{raw_count}**\n")
    md.append(f"- Alive hosts (httpx): **{alive_count}**\n")
    md.append(f"- Final hosts used: **{final_count}**\n")

    md.append("### Final Hosts (preview)\n")
    if final_preview:
        md.append(";\n")
        md.extend([h + "\n" for h in final_preview])
        md.append(";\n")
    else:
        md.append("_No hosts in hosts_final.txt_\n")

    md.append("## Vulnerability Scan (Nuclei)\n")
    md.append(f"- Findings count: **{nuclei_count}**\n")

    if nuclei_count > 0:
        md.append("### Nuclei Findings (preview)\n")
        md.append(";\n")
        md.extend([x + "\n" for x in nuclei_preview])
        md.append(";\n")
    else:
        md.append("✅ No findings in FAST profile output.\n\n")
        md.append("**Possible reasons:**\n")
        md.append("- No High/Critical vulnerabilities detected\n")
        md.append("- WAF/Cloudflare blocking responses (403/429/timeouts)\n")
        md.append("- Nuclei templates outdated\n\n")
        md.append(f"Check the log file: ;{nuclei_log};\n")

    md.append("## Evidence & Cleanup\n")
    md.append(f"- Evidence captured: **{ctx.get('evidence', True)}**\n")
    md.append(f"- Cleanup done: **{ctx.get('cleanup', True)}**\n")

    md.append("## Output Files\n")
    md.append(f"- ;{hosts_raw};\n")
    md.append(f"- ;{hosts_alive};\n")
    md.append(f"- ;{hosts_final};\n")
    md.append(f"- ;{nuclei_txt};\n")
    md.append(f"- ;{nuclei_log};\n")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("".join(md))

    ok(f"Report generated: {report_path}")
