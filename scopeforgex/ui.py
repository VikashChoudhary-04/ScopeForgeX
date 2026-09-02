"""
ScopeForgeX User Interface
==========================

Rich-based console helpers used throughout ScopeForgeX.

Provides consistent banners, stage headers, status messages,
and summary tables.

v0.4.0
"""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from collections import Counter
from typing import Any, Mapping

console = Console()


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

def _status(icon: str, color: str, message: str):
    """
    Print a standardized status message.
    """

    console.print(f"[{color}][{icon}][/{color}] {message}")


# ----------------------------------------------------------------------
# Public UI
# ----------------------------------------------------------------------

def banner():
    """
    Display the ScopeForgeX startup banner.
    """

    title = Text("ScopeForgeX", style="bold green")
    subtitle = Text(
        "CLI-only Workflow Automation (Safe Mode)",
        style="cyan",
    )

    console.print(
        Panel.fit(
            Text.assemble(title, "\n", subtitle),
            border_style="green",
        )
    )


def stage(title: str, color: str = "blue"):
    """
    Display a stage header.
    """

    console.print()

    console.print(
        Panel.fit(
            f"[bold {color}]{title}[/bold {color}]",
            border_style=color,
        )
    )


def info(message: str):
    """
    Display an informational message.
    """

    _status("*", "cyan", message)


def ok(message: str):
    """
    Display a success message.
    """

    _status("✔", "green", message)


def warn(message: str):
    """
    Display a warning message.
    """

    _status("!", "yellow", message)


def err(message: str):
    """
    Display an error message.
    """

    _status("✘", "red", message)


def summary_table(
    title: str,
    rows: list[tuple[str, str]],
):
    """
    Display a two-column summary table.
    """

    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
    )

    table.add_column(
        "Item",
        style="bold",
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    for key, value in rows:
        table.add_row(
            str(key),
            str(value),
        )

    console.print(table)
# ----------------------------------------------------------------------
# Finding-first assessment presentation
# ----------------------------------------------------------------------

_SEVERITY_ORDER = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "as_dict"):
        try:
            data = value.as_dict()
            if isinstance(data, Mapping):
                return dict(data)
        except Exception:
            pass
    return {}


def _finding_id(finding: Mapping[str, Any]) -> str:
    return str(
        finding.get(
            "finding_id",
            finding.get("id", ""),
        )
        or ""
    )


def _finding_title(finding: Mapping[str, Any]) -> str:
    return str(
        finding.get("title", "Untitled Finding")
        or "Untitled Finding"
    )


def _finding_severity(finding: Mapping[str, Any]) -> str:
    value = str(
        finding.get("severity", "Informational")
        or "Informational"
    ).strip().lower()

    aliases = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }

    return aliases.get(
        value,
        value.title(),
    )


def _finding_asset(finding: Mapping[str, Any]) -> str:
    for key in ("url", "host", "target"):
        value = finding.get(key)
        if value:
            return str(value)
    return "Unspecified"


def _finding_cve(finding: Mapping[str, Any]) -> str:
    value = finding.get("cve")
    if value:
        return str(value)

    metadata = finding.get("metadata")
    if isinstance(metadata, Mapping):
        values = metadata.get("cves")
        if isinstance(values, (list, tuple, set)):
            for item in values:
                if str(item).strip():
                    return str(item).strip()

    return ""


def _severity_style(severity: str) -> str:
    return {
        "Critical": "bold white on red",
        "High": "bold white on dark_orange",
        "Medium": "bold black on yellow",
        "Low": "bold black on green",
        "Informational": "bold white on blue",
    }.get(
        severity,
        "bold white on grey37",
    )


def _finding_panel(
    finding: Mapping[str, Any],
    index: int,
) -> Panel:
    finding_id = (
        _finding_id(finding)
        or f"SF-{index:03d}"
    )
    severity = _finding_severity(finding)

    table = Table(
        box=None,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Field", style="grey70", no_wrap=True)
    table.add_column("Value", ratio=1)

    table.add_row(
        "Severity",
        Text(
            severity,
            style=_severity_style(severity),
        ),
    )
    table.add_row(
        "Confidence",
        str(
            finding.get(
                "confidence",
                "Informational",
            )
        ),
    )
    table.add_row(
        "Status",
        str(
            finding.get(
                "status",
                "Open",
            )
        ),
    )
    table.add_row(
        "Affected",
        _finding_asset(finding),
    )

    cve = _finding_cve(finding)
    if cve:
        table.add_row("CVE", cve)

    source = finding.get("source_tool")
    if source:
        table.add_row("Detection", str(source))

    return Panel(
        table,
        title=f"{finding_id} — {_finding_title(finding)}",
        border_style={
            "Critical": "red",
            "High": "dark_orange",
            "Medium": "yellow",
            "Low": "green",
            "Informational": "blue",
        }.get(severity, "grey50"),
        padding=(0, 1),
    )


def assessment_summary(
    ctx: Mapping[str, Any],
) -> None:
    """
    Render the final assessment as a security-first terminal dashboard.

    Operational telemetry remains available below the findings so the operator
    sees the security result before execution details.
    """

    findings = [
        _mapping(item)
        for item in (ctx.get("findings") or [])
    ]

    findings = [
        item
        for item in findings
        if item
    ]

    findings.sort(
        key=lambda item: (
            {
                "Critical": 0,
                "High": 1,
                "Medium": 2,
                "Low": 3,
                "Informational": 4,
            }.get(_finding_severity(item), 5),
            _finding_title(item).lower(),
            _finding_id(item),
        )
    )

    counts = Counter(
        _finding_severity(item)
        for item in findings
    )

    cves = sorted(
        {
            _finding_cve(item)
            for item in findings
            if _finding_cve(item)
        }
    )

    assets = sorted(
        {
            _finding_asset(item)
            for item in findings
        }
    )

    highest = next(
        (
            severity
            for severity in _SEVERITY_ORDER
            if counts.get(severity, 0)
        ),
        None,
    )

    risk_text = highest or "No Material Finding"
    risk_style = (
        _severity_style(highest)
        if highest
        else "bold green"
    )

    renderables: list[Any] = [
        Panel(
            Text.assemble(
                ("SCOPEFORGEX\n", "bold white"),
                ("Security Assessment Complete", "bold cyan"),
            ),
            subtitle=(
                f"target={ctx.get('target', '-')}"
                f"  •  profile={ctx.get('profile', '-')}"
            ),
            border_style="cyan",
            padding=(1, 2),
        )
    ]

    metrics = Table(
        box=box.ROUNDED,
        expand=True,
    )
    for title in (
        "Findings",
        "Critical",
        "High",
        "Medium",
        "Low",
        "CVEs",
        "Assets",
    ):
        metrics.add_column(
            title,
            justify="center",
        )

    metrics.add_row(
        str(len(findings)),
        str(counts.get("Critical", 0)),
        str(counts.get("High", 0)),
        str(counts.get("Medium", 0)),
        str(counts.get("Low", 0)),
        str(len(cves)),
        str(len(assets)),
    )

    renderables.append(
        Panel(
            metrics,
            title="Security Overview",
            border_style="white",
        )
    )

    renderables.append(
        Panel(
            Text(
                risk_text,
                style=risk_style,
                justify="center",
            ),
            title="Highest Observed Severity",
            border_style="white",
        )
    )

    if findings:
        top = Group(
            *[
                _finding_panel(
                    finding,
                    index,
                )
                for index, finding in enumerate(
                    findings[:8],
                    start=1,
                )
            ]
        )
        renderables.append(
            Panel(
                top,
                title=(
                    "Findings"
                    if len(findings) <= 8
                    else f"Top Findings — showing 8 of {len(findings)}"
                ),
                border_style="cyan",
            )
        )
    else:
        renderables.append(
            Panel(
                Text(
                    "No vulnerabilities or security findings were identified "
                    "by the automated assessment.",
                    style="bold green",
                    justify="center",
                ),
                title="Assessment Result",
                border_style="green",
            )
        )

    report_paths = ctx.get("report_paths") or {}
    if report_paths:
        report_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
        )
        report_table.add_column(
            "View",
            style="grey70",
            no_wrap=True,
        )
        report_table.add_column(
            "Path",
            ratio=1,
        )

        report_keys = (
            ("Professional", "professional_markdown"),
            ("Professional HTML", "professional_html"),
            ("Findings", "findings_markdown"),
            ("Findings HTML", "findings_html"),
            ("Canonical JSON", "canonical_json"),
        )

        for label, key in report_keys:
            path = report_paths.get(key)
            if path:
                report_table.add_row(
                    label,
                    str(path),
                )

        if report_table.row_count:
            renderables.append(
                Panel(
                    report_table,
                    title="Reports",
                    border_style="blue",
                )
            )

    execution_results = (
        ctx.get("execution_results") or []
    )

    if execution_results:
        execution_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
        )
        execution_table.add_column("Tool")
        execution_table.add_column("Status")
        execution_table.add_column(
            "Duration",
            justify="right",
        )

        for result in execution_results:
            data = _mapping(result)
            if not data:
                continue

            status = str(
                data.get(
                    "status",
                    "unknown",
                )
            )

            duration = data.get(
                "duration",
                data.get(
                    "duration_seconds",
                    0,
                ),
            )

            try:
                duration_text = f"{float(duration):.2f}s"
            except (
                TypeError,
                ValueError,
            ):
                duration_text = str(duration)

            execution_table.add_row(
                str(
                    data.get(
                        "tool",
                        "unknown",
                    )
                ),
                Text(
                    status.upper(),
                    style=(
                        "bold green"
                        if status.lower() == "success"
                        else "bold red"
                    ),
                ),
                duration_text,
            )

        if execution_table.row_count:
            renderables.append(
                Panel(
                    execution_table,
                    title="Execution Coverage",
                    border_style="grey50",
                )
            )

    console.print(
        Group(
            *renderables
        )
    )


###############################################################################
# Public API
###############################################################################

__all__ = [
    "banner",
    "stage",
    "info",
    "ok",
    "warn",
    "err",
    "summary_table",
    "assessment_summary",
]
