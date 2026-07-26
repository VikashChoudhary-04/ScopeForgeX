"""
ScopeForgeX Stage 6
===================

Reporting stage.

Collects workflow results and delegates Markdown rendering
to the reporting engine.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime

from reporting.models import (
    ReportData,
    ScanStatistics,
    StageResult,
)
from reporting.report_generator import ReportGenerator

from scopeforgex.ui import ok, stage


def _count_lines(path: str | None) -> int:
    if not path:
        return 0
    p = Path(path)
    if not p.exists():
        return 0
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for line in f if line.strip())


def _existing_files(paths: list[str | None]) -> list[str]:
    return [p for p in paths if p and Path(p).exists()]


def stage6_reporting(ctx: dict):
    stage("STAGE 6 — REPORTING", "magenta")

    outdir = Path(ctx.get("outdir", "outputs/unknown"))
    report_path = outdir / "report.md"

    pipeline = ctx.get("pipeline", {})

    hosts_raw = pipeline.get("hosts_raw")
    hosts_alive = pipeline.get("hosts_alive")
    hosts_final = pipeline.get("hosts_final")
    urls_final = pipeline.get("urls_final")

    vuln_dir = outdir / "vuln"

    nuclei_txt = str(vuln_dir / "nuclei.txt")
    nuclei_hosts = str(vuln_dir / "nuclei_hosts.txt")
    nuclei_urls = str(vuln_dir / "nuclei_urls.txt")
    nuclei_hosts_log = str(vuln_dir / "nuclei_hosts.log")
    nuclei_urls_log = str(vuln_dir / "nuclei_urls.log")

    generated_files = _existing_files([
        hosts_raw,
        hosts_alive,
        hosts_final,
        urls_final,
        nuclei_txt,
        nuclei_hosts,
        nuclei_urls,
        nuclei_hosts_log,
        nuclei_urls_log,
    ])

    stats = ScanStatistics(
        subdomains_found=_count_lines(hosts_raw),
        alive_hosts=_count_lines(hosts_alive),
        final_hosts=_count_lines(hosts_final),
        urls_discovered=_count_lines(urls_final),
        nuclei_findings=_count_lines(nuclei_txt),
        files_generated=len(generated_files),
    )

    report = ReportData(
        target=ctx.get("target", "-"),
        profile=ctx.get("profile", "-"),
        target_type=ctx.get("target_type", "-"),
        start_time=datetime.now(),
        end_time=datetime.now(),
        statistics=stats,
        generated_files=generated_files,
    )

    report.stages.extend([
        StageResult("Scope", True),
        StageResult("Reconnaissance", True),
        StageResult("Vulnerability Identification", True),
        StageResult("Reporting", True),
    ])

    if stats.alive_hosts == 0:
        report.warnings.append(
            "No live hosts were identified. Downstream discovery may have been skipped."
        )

    if stats.nuclei_findings == 0:
        report.warnings.append(
            "No automated vulnerability findings were recorded."
        )

    ReportGenerator(report).generate_markdown(str(report_path))

    ok(f"Report generated: {report_path}")
