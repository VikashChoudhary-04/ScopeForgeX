"""
ScopeForgeX Stage 6
===================

Reporting stage.

Generates a Markdown report summarizing the assessment and
the pipeline outputs.

v0.4.0
"""

from __future__ import annotations

from pathlib import Path

from scopeforgex.ui import ok, stage


def _count_lines(path: str | None) -> int:
    """
    Count non-empty lines in a text file.
    """

    if not path:
        return 0

    file = Path(path)

    if not file.exists():
        return 0

    with file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as infile:
        return sum(1 for line in infile if line.strip())


def _read_preview(
    path: str | None,
    limit: int = 20,
) -> list[str]:
    """
    Read up to 'limit' non-empty lines from a file.
    """

    if not path:
        return []

    file = Path(path)

    if not file.exists():
        return []

    with file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as infile:
        return [
            line.strip()
            for line in infile
            if line.strip()
        ][:limit]


def _existing_files(paths: list[str | None]) -> list[str]:
    """
    Return existing files from the supplied list.
    """

    return [
        path
        for path in paths
        if path and Path(path).exists()
    ]


def stage6_reporting(ctx: dict):
    """
    Generate the final assessment report.
    """

    stage("STAGE 6 — REPORTING", "magenta")

    outdir = Path(ctx.get("outdir", "outputs/unknown"))
    report_path = outdir / "report.md"

    pipeline = ctx.get("pipeline", {})

    hosts_raw = pipeline.get("hosts_raw")
    hosts_alive = pipeline.get("hosts_alive")
    hosts_final = pipeline.get("hosts_final")
    urls_raw = pipeline.get("urls_raw")
    urls_final = pipeline.get("urls_final")

    vuln_dir = outdir / "vuln"

    nuclei_txt = str(vuln_dir / "nuclei.txt")
    nuclei_hosts = str(vuln_dir / "nuclei_hosts.txt")
    nuclei_urls = str(vuln_dir / "nuclei_urls.txt")
    nuclei_hosts_log = str(vuln_dir / "nuclei_hosts.log")
    nuclei_urls_log = str(vuln_dir / "nuclei_urls.log")

    generated_files = _existing_files(
        [
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
        ]
    )

    report: list[str] = []

    report.append("# ScopeForgeX Report\n\n")

    report.append("## Assessment Context\n\n")
    report.append(f"- **Target:** `{ctx.get('target', '-')}`\n")
    report.append(f"- **Profile:** `{ctx.get('profile', '-')}`\n")
    report.append(f"- **Target Type:** `{ctx.get('target_type', '-')}`\n\n")

    report.append("## Recon Summary\n\n")
    report.append(f"- Raw hosts discovered: **{_count_lines(hosts_raw)}**\n")
    report.append(f"- Alive hosts identified: **{_count_lines(hosts_alive)}**\n")
    report.append(f"- Final hosts available downstream: **{_count_lines(hosts_final)}**\n")
    report.append(f"- Final URLs discovered: **{_count_lines(urls_final)}**\n\n")

    report.append("### Final Hosts Preview\n\n")

    hosts_preview = _read_preview(hosts_final)

    if hosts_preview:
        report.append("```text\n")
        report.extend(f"{host}\n" for host in hosts_preview)
        report.append("```\n\n")
    else:
        report.append("_No hosts are present in `hosts_final.txt`._\n\n")

    report.append("## Vulnerability Identification\n\n")

    nuclei_count = _count_lines(nuclei_txt)

    report.append(f"- Nuclei findings recorded: **{nuclei_count}**\n\n")

    nuclei_preview = _read_preview(
        nuclei_txt,
        limit=30,
    )

    if nuclei_preview:
        report.append("### Nuclei Findings Preview\n\n")
        report.append("```text\n")
        report.extend(f"{finding}\n" for finding in nuclei_preview)
        report.append("```\n\n")
    else:
        report.append(
            "_No Nuclei findings were recorded in the combined findings file._\n\n"
        )
        report.append(
            "An empty findings file does not by itself prove that the target "
            "has no vulnerabilities. Review the scan logs for execution "
            "errors, timeouts, filtering, or other limitations.\n\n"
        )

    report.append("## Generated Output Files\n\n")

    if generated_files:
        report.extend(
            f"- `{path}`\n"
            for path in generated_files
        )
    else:
        report.append(
            "- No tracked pipeline output files were found.\n"
        )

    with report_path.open(
        "w",
        encoding="utf-8",
    ) as outfile:
        outfile.write("".join(report))

    ok(f"Report generated: {report_path}")
