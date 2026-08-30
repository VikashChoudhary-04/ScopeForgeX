"""
ScopeForgeX — Stage 6 Reporting & Cleanup
=========================================

Stage 6 of the ScopeForgeX ethical hacking workflow.

Responsibilities
----------------

- Collect final workflow metadata.
- Aggregate execution results and assessment findings.
- Generate the final Markdown and JSON reports.
- Preserve generated artifacts.
- Present a concise completion summary.
- Perform safe workflow cleanup without deleting assessment evidence.

Architecture
------------

Stages 0–5
    |
    v
Stage 6
    |
    +--> Findings
    +--> Execution Results
    +--> Statistics
    +--> Warnings / Errors
    +--> ReportData
            |
            +--> Markdown
            +--> JSON

Design Principles
-----------------

- Reporting consumes structured workflow data.
- Reporting does not execute assessment tools.
- Reporting does not perform network requests.
- Reporting does not independently classify vulnerabilities.
- Original findings remain available.
- Generated evidence is preserved.
- Report generation failures are reported explicitly.
- Cleanup must never silently remove assessment evidence.
- Markdown and JSON reports represent the same final assessment state.

v1.3.0
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from scopeforgex.ui import (
    err,
    info,
    ok,
    stage,
    warn,
)


###############################################################################
# Helpers
###############################################################################


def _utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


def _count_lines(
    path: str,
) -> int:
    """
    Count non-empty lines in a text file.

    Missing or unreadable files return zero so reporting can continue when an
    optional tool did not produce an artifact.
    """

    if not os.path.isfile(
        path
    ):
        return 0

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            return sum(
                1
                for line in handle
                if line.strip()
            )

    except OSError:
        return 0


def _read_preview(
    path: str,
    limit: int = 30,
) -> list[str]:
    """
    Read a bounded preview from a text artifact.
    """

    if not os.path.isfile(
        path
    ):
        return []

    lines: list[str] = []

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as handle:

            for line in handle:

                value = line.rstrip()

                if not value:
                    continue

                lines.append(
                    value
                )

                if len(
                    lines
                ) >= limit:
                    break

    except OSError:
        return []

    return lines


def _json_default(
    value: Any,
) -> Any:
    """
    Convert common ScopeForgeX values into JSON-compatible values.
    """

    if isinstance(
        value,
        datetime,
    ):
        return value.isoformat()

    if hasattr(
        value,
        "as_dict",
    ):
        return value.as_dict()

    if hasattr(
        value,
        "__dict__",
    ):
        return vars(
            value
        )

    return str(
        value
    )


###############################################################################
# Report Data Collection
###############################################################################


def _collect_report_data(
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a serializable report data structure from workflow context.

    Existing structured report data is preferred when available. Additional
    runtime metadata is included without mutating the original context.
    """

    report_data: dict[str, Any] = {}

    existing = ctx.get(
        "report_data"
    )

    if isinstance(
        existing,
        dict,
    ):
        report_data.update(
            existing
        )

    report_data.setdefault(
        "target",
        ctx.get(
            "target",
            "",
        ),
    )

    report_data.setdefault(
        "profile",
        ctx.get(
            "profile",
            "",
        ),
    )

    report_data.setdefault(
        "target_type",
        ctx.get(
            "target_type",
            "",
        ),
    )

    report_data.setdefault(
        "generated_at",
        _utc_now().isoformat(),
    )

    return report_data


###############################################################################
# Markdown Report
###############################################################################


def _build_markdown_report(
    ctx: dict[str, Any],
) -> str:
    """
    Build the final Markdown report.

    The renderer remains intentionally conservative: it summarizes known
    structured workflow data and selected artifact statistics without
    inventing vulnerability findings.
    """

    outdir = str(
        ctx.get(
            "outdir",
            ".",
        )
    )

    target = str(
        ctx.get(
            "target",
            "",
        )
    )

    profile = str(
        ctx.get(
            "profile",
            "",
        )
    )

    recon_dir = os.path.join(
        outdir,
        "recon",
    )

    vuln_dir = os.path.join(
        outdir,
        "vuln",
    )

    hosts_alive = os.path.join(
        recon_dir,
        "hosts_alive.txt",
    )

    nuclei_txt = os.path.join(
        vuln_dir,
        "nuclei.txt",
    )

    nuclei_log = os.path.join(
        vuln_dir,
        "nuclei.log",
    )

    alive_count = _count_lines(
        hosts_alive
    )

    nuclei_count = _count_lines(
        nuclei_txt
    )

    nuclei_preview = _read_preview(
        nuclei_txt,
        30,
    )

    report_data = _collect_report_data(
        ctx
    )

    md: list[str] = []

    md.append(
        "# ScopeForgeX Assessment Report\n"
    )

    md.append(
        f"- **Target:** {target}\n"
    )

    md.append(
        f"- **Profile:** {profile}\n"
    )

    md.append(
        f"- **Generated:** "
        f"{report_data.get('generated_at', '')}\n"
    )

    md.append(
        "\n## Reconnaissance\n"
    )

    md.append(
        f"- Alive hosts (httpx): **{alive_count}**\n"
    )

    md.append(
        "\n## Vulnerability Identification\n"
    )

    md.append(
        f"- Findings count: **{nuclei_count}**\n"
    )

    if nuclei_count > 0:

        md.append(
            "\n### Nuclei Findings Preview\n"
        )

        md.append(
            "```text\n"
        )

        md.extend(
            f"{line}\n"
            for line in nuclei_preview
        )

        md.append(
            "```\n"
        )

    else:

        md.append(
            "\n- No Nuclei findings were recorded in the "
            "available text artifact.\n"
        )

    if os.path.exists(
        nuclei_log
    ):

        md.append(
            "\n## Vulnerability Scanner Log\n"
        )

        md.append(
            f"- `{nuclei_log}`\n"
        )

    warnings = ctx.get(
        "warnings",
        [],
    )

    errors = ctx.get(
        "errors",
        [],
    )

    if warnings:

        md.append(
            "\n## Warnings\n"
        )

        for warning in warnings:

            md.append(
                f"- {warning}\n"
            )

    if errors:

        md.append(
            "\n## Errors\n"
        )

        for error in errors:

            md.append(
                f"- {error}\n"
            )

    md.append(
        "\n## Artifacts\n"
    )

    md.append(
        f"- Output directory: `{outdir}`\n"
    )

    return "".join(
        md
    )


###############################################################################
# JSON Report
###############################################################################


def _build_json_report(
    ctx: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the final JSON report structure.

    Structured result objects are serialized through their ``as_dict`` method
    when available.
    """

    report_data = _collect_report_data(
        ctx
    )

    report: dict[str, Any] = dict(
        report_data
    )

    for key in (
        "findings",
        "results",
        "warnings",
        "errors",
        "artifacts",
        "statistics",
        "stage_results",
    ):

        value = ctx.get(
            key
        )

        if value is None:
            continue

        if isinstance(
            value,
            list,
        ):

            report[key] = [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in value
            ]

        elif hasattr(
            value,
            "as_dict",
        ):

            report[key] = value.as_dict()

        else:

            report[key] = value

    return report


###############################################################################
# Report Generation
###############################################################################


def _write_report_files(
    ctx: dict[str, Any],
) -> tuple[str, str]:
    """
    Write Markdown and JSON reports.

    Returns:
        Tuple containing Markdown and JSON report paths.
    """

    outdir = str(
        ctx.get(
            "outdir",
            ".",
        )
    )

    os.makedirs(
        outdir,
        exist_ok=True,
    )

    markdown_path = os.path.join(
        outdir,
        "report.md",
    )

    json_path = os.path.join(
        outdir,
        "report.json",
    )

    markdown = _build_markdown_report(
        ctx
    )

    report_json = _build_json_report(
        ctx
    )

    with open(
        markdown_path,
        "w",
        encoding="utf-8",
    ) as handle:

        handle.write(
            markdown
        )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            report_json,
            handle,
            indent=2,
            ensure_ascii=False,
            default=_json_default,
        )

    return (
        markdown_path,
        json_path,
    )


###############################################################################
# Stage 6
###############################################################################


def stage6_report_cleanup(
    ctx: dict[str, Any],
) -> None:
    """
    Execute Stage 6 reporting and safe cleanup.

    Reporting is performed before cleanup so that all available workflow
    information is represented in the final artifacts.
    """

    stage(
        "STAGE 6 — REPORTING & CLEANUP",
        "green",
    )

    try:

        markdown_path, json_path = _write_report_files(
            ctx
        )

        info(
            f"Markdown report: {markdown_path}"
        )

        info(
            f"JSON report: {json_path}"
        )

        generated_files = ctx.setdefault(
            "generated_files",
            [],
        )

        for path in (
            markdown_path,
            json_path,
        ):

            if path not in generated_files:
                generated_files.append(
                    path
                )

        ok(
            "Reports generated successfully."
        )

    except Exception as exc:

        err(
            f"Report generation failed: {exc}"
        )

        ctx.setdefault(
            "errors",
            [],
        ).append(
            f"Stage 6 reporting failed: {exc}"
        )

        return

    # Cleanup is intentionally conservative. Assessment artifacts are retained
    # by default because they may be required for validation, reproduction,
    # reporting, or audit purposes.
    warn(
        "Cleanup skipped: assessment artifacts are preserved."
    )

    ok(
        "Stage 6 reporting and cleanup finished."
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage6_report_cleanup",
]
