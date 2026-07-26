"""
Enhanced Stage 6 Reporting (v2)

Collects workflow metadata and delegates rendering to ReportGenerator.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path

from reporting.models import ReportData, ScanStatistics, StageResult
from reporting.report_generator import ReportGenerator
from scopeforgex.ui import ok, stage


def _count(path):
    if not path or not Path(path).exists():
        return 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for line in f if line.strip())


def _existing(paths):
    return [p for p in paths if p and Path(p).exists()]


def stage6_reporting(ctx):
    stage("STAGE 6 — REPORTING", "magenta")

    outdir = Path(ctx["outdir"])
    report_path = outdir / "report.md"

    recon = outdir / "recon"
    vuln = outdir / "vuln"

    hosts_raw = recon / "hosts_raw.txt"
    hosts_alive = recon / "hosts_alive.txt"
    hosts_final = recon / "hosts_final.txt"
    urls_final = recon / "urls_final.txt"

    nuclei = vuln / "nuclei.txt"
    nuclei_hosts = vuln / "nuclei_hosts.txt"
    nuclei_urls = vuln / "nuclei_urls.txt"

    artifacts = _existing([
        str(hosts_raw),
        str(hosts_alive),
        str(hosts_final),
        str(urls_final),
        str(nuclei),
        str(nuclei_hosts),
        str(nuclei_urls),
    ])

    stats = ScanStatistics(
        subdomains_found=_count(hosts_raw),
        alive_hosts=_count(hosts_alive),
        final_hosts=_count(hosts_final),
        urls_discovered=_count(urls_final),
        nuclei_findings=_count(nuclei),
        files_generated=len(artifacts),
    )

    start = ctx.get("workflow_start_time", time.time())
    end = time.time()

    report = ReportData(
        target=ctx.get("target", "-"),
        profile=ctx.get("profile", "-"),
        target_type=ctx.get("target_type", "-"),
        start_time=datetime.fromtimestamp(start),
        end_time=datetime.fromtimestamp(end),
        statistics=stats,
        generated_files=artifacts,
    )

    report.duration_seconds = end - start

    report.stages = [
        StageResult("Scope", "Completed"),
        StageResult("Reconnaissance", "Completed"),
        StageResult(
            "Validation",
            "Completed" if stats.alive_hosts else "Skipped",
        ),
        StageResult(
            "Vulnerability Identification",
            "Completed" if stats.alive_hosts else "Skipped",
        ),
        StageResult("Reporting", "Completed"),
    ]

    report.tool_results = {
        "Subfinder": "Completed",
        "httpx": "Completed" if stats.alive_hosts else "No Live Hosts",
        "Katana": "Skipped" if not stats.alive_hosts else "Completed",
        "Nuclei": "Skipped" if not stats.alive_hosts else "Completed",
    }

    report.warnings = []

    if not stats.alive_hosts:
        report.warnings.append(
            "No live hosts were identified. Validation and vulnerability stages were skipped."
        )

    if not stats.nuclei_findings:
        report.warnings.append(
            "No automated vulnerability findings were recorded."
        )

    ReportGenerator(report).generate_markdown(str(report_path))
    ok(f"Report written to {report_path}")
