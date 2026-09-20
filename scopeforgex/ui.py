"""
ScopeForgeX User Interface
==========================

Rich-based console helpers used throughout ScopeForgeX.

Provides consistent banners, stage headers, status messages,
workflow execution events, assessment context, readiness state,
summary tables, and a security-first final assessment dashboard.

v0.4.0
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


# ----------------------------------------------------------------------
# UI Design System
# ----------------------------------------------------------------------


_UI_RULE_WIDTH = 70
_UI_LABEL_WIDTH = 16


def _ui_rule(
    char: str = "─",
    width: int = _UI_RULE_WIDTH,
) -> str:
    """
    Return a deterministic horizontal UI rule.
    """

    return char * width


def _ui_section(
    title: str,
) -> Group:
    """
    Build a consistent section heading.
    """

    return Group(
        Text(
            _ui_rule(),
            style="dim",
        ),
        Text(
            str(title).strip().upper(),
            style="bold",
        ),
        Text(
            _ui_rule(),
            style="dim",
        ),
    )


def _ui_label_value(
    label: str,
    value: Any,
) -> Text:
    """
    Build a consistently aligned label/value line.
    """

    text = Text()

    text.append(
        f"{str(label):<{_UI_LABEL_WIDTH}}",
        style="bold",
    )

    text.append(
        str(value)
    )

    return text


def _ui_status_line(
    status: str,
    message: Any,
) -> Text:
    """
    Build a consistent status/event line.
    """

    normalized = str(
        status
    ).strip().upper()

    styles = {
        "INFO": "cyan",
        "OK": "green",
        "SUCCESS": "green",
        "SKIPPED": "grey70",
        "SKIP": "grey70",
        "WARN": "yellow",
        "WARNING": "yellow",
        "ERROR": "red",
        "ERR": "red",
        "FAILED": "red",
        "FAIL": "red",
    }

    symbols = {
        "INFO": "·",
        "OK": "✓",
        "SUCCESS": "✓",
        "SKIPPED": "⊘",
        "SKIP": "⊘",
        "WARN": "!",
        "WARNING": "!",
        "ERROR": "✗",
        "ERR": "✗",
        "FAILED": "✗",
        "FAIL": "✗",
    }

    display_status = {
        "SUCCESS": "OK",
        "WARNING": "WARN",
        "ERR": "ERROR",
        "FAILED": "FAILED",
        "FAIL": "FAILED",
        "SKIP": "SKIPPED",
    }.get(
        normalized,
        normalized,
    )

    text = Text()

    text.append(
        f"{symbols.get(normalized, '•')} ",
        style=(
            f"bold "
            f"{styles.get(normalized, 'white')}"
        ),
    )

    text.append(
        f"{display_status:<6}",
        style="bold",
    )

    text.append(
        str(message)
    )

    return text


def _ui_panel_title(
    title: str,
    subtitle: str | None = None,
) -> Text:
    """
    Build a consistent panel title.
    """

    text = Text()

    text.append(
        str(title).upper(),
        style="bold",
    )

    if subtitle:
        text.append(
            f"  {subtitle}",
            style="dim",
        )

    return text


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------


def _status(
    icon: str,
    color: str,
    message: str,
):
    """
    Print a standardized status message.

    The helper is retained for compatibility with existing internal
    callers.
    """

    console.print(
        f"[{color}][{icon}][/{color}] {message}"
    )


def _mapping(
    value: Any,
) -> dict[str, Any]:
    """
    Convert a mapping-like object into a dictionary.
    """

    if isinstance(
        value,
        Mapping,
    ):
        return dict(value)

    if hasattr(
        value,
        "as_dict",
    ):
        try:
            data = value.as_dict()

            if isinstance(
                data,
                Mapping,
            ):
                return dict(data)

        except Exception:
            pass

    return {}


def _finding_id(
    finding: Mapping[str, Any],
) -> str:
    """
    Return the canonical finding identifier when available.
    """

    return str(
        finding.get(
            "finding_id",
            finding.get(
                "id",
                "",
            ),
        )
        or ""
    )


def _finding_title(
    finding: Mapping[str, Any],
) -> str:
    """
    Return a display-safe finding title.
    """

    return str(
        finding.get(
            "title",
            "Untitled Finding",
        )
        or "Untitled Finding"
    )


def _finding_severity(
    finding: Mapping[str, Any],
) -> str:
    """
    Normalize finding severity for consistent terminal presentation.
    """

    value = str(
        finding.get(
            "severity",
            "Informational",
        )
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


def _finding_asset(
    finding: Mapping[str, Any],
) -> str:
    """
    Return the most specific available affected asset.
    """

    for key in (
        "url",
        "host",
        "target",
    ):
        value = finding.get(key)

        if value:
            return str(value)

    return "Unspecified"


def _finding_cve(
    finding: Mapping[str, Any],
) -> str:
    """
    Return the first available CVE associated with a finding.
    """

    value = finding.get("cve")

    if value:
        return str(value)

    metadata = finding.get("metadata")

    if isinstance(
        metadata,
        Mapping,
    ):
        values = metadata.get("cves")

        if isinstance(
            values,
            (
                list,
                tuple,
                set,
            ),
        ):
            for item in values:
                if str(item).strip():
                    return str(item).strip()

    return ""


def _severity_style(
    severity: str,
) -> str:
    """
    Return the terminal style for a normalized severity.
    """

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


def _intelligence_mapping(
    value: Any,
) -> dict[str, Any]:
    """
    Convert a vulnerability-intelligence result into a mapping.

    Intelligence results may be dataclass instances exposing ``as_dict``.
    """

    return _mapping(value)


def _intelligence_metadata(
    value: Mapping[str, Any],
) -> Mapping[str, Any]:
    """
    Return normalized vulnerability-intelligence metadata.

    Intelligence-specific attributes such as product, version, CPE,
    CVSS and KEV are stored inside the CollectorObservation metadata.
    """

    metadata = value.get(
        "metadata",
        {},
    )

    if isinstance(
        metadata,
        Mapping,
    ):
        return metadata

    return {}


def _intelligence_cve(
    value: Mapping[str, Any],
) -> str:
    """
    Return the CVE identifier from an intelligence result.
    """

    return str(
        value.get(
            "cve",
            value.get(
                "value",
                "",
            ),
        )
        or ""
    ).strip()


def _intelligence_product(
    value: Mapping[str, Any],
) -> str:
    """
    Return the observed product from an intelligence result.
    """

    metadata = _intelligence_metadata(
        value
    )

    return str(
        metadata.get(
            "product",
            "",
        )
        or ""
    ).strip()


def _intelligence_version(
    value: Mapping[str, Any],
) -> str:
    """
    Return the observed software version when available.
    """

    metadata = _intelligence_metadata(
        value
    )

    return str(
        metadata.get(
            "version",
            "",
        )
        or ""
    ).strip()


def _intelligence_cpe(
    value: Mapping[str, Any],
) -> str:
    """
    Return the CPE associated with an intelligence result.
    """

    metadata = _intelligence_metadata(
        value
    )

    return str(
        metadata.get(
            "cpe",
            "",
        )
        or ""
    ).strip()


def _intelligence_severity(
    value: Mapping[str, Any],
) -> str:
    """
    Return the intelligence severity when available.
    """

    severity = str(
        value.get(
            "severity",
            "Informational",
        )
        or "Informational"
    ).strip()

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
        severity.lower(),
        severity.title(),
    )


def _intelligence_cvss(
    value: Mapping[str, Any],
) -> str:
    """
    Return the CVSS score and version for display.
    """

    metadata = _intelligence_metadata(
        value
    )

    score = metadata.get(
        "cvss_score"
    )

    if score is None:
        return "-"

    version = str(
        metadata.get(
            "cvss_version",
            "",
        )
        or ""
    ).strip()

    if version:
        return f"{score} ({version})"

    return str(score)


def _intelligence_kev(
    value: Mapping[str, Any],
) -> bool:
    """
    Return whether the intelligence result is present in CISA KEV.
    """

    metadata = _intelligence_metadata(
        value
    )

    return metadata.get(
        "kev"
    ) is True


def _intelligence_asset(
    value: Mapping[str, Any],
) -> str:
    """
    Return the most specific target asset associated with intelligence.
    """

    for key in (
        "url",
        "host",
        "target",
    ):
        item = value.get(key)

        if item:
            return str(item)

    return "Unspecified"


def _intelligence_records(
    values: Any,
) -> list[dict[str, Any]]:
    """
    Normalize vulnerability-intelligence results for terminal rendering.
    """

    if not values:
        return []

    records: list[dict[str, Any]] = []

    for value in values:
        record = _intelligence_mapping(
            value
        )

        if record:
            records.append(record)

    return records


def _intelligence_counts(
    values: Any,
) -> dict[str, int]:
    """
    Calculate compact vulnerability-intelligence dashboard counters.

    Intelligence-specific fields are read from the canonical metadata
    structure used by CollectorObservation.
    """

    records = _intelligence_records(
        values
    )

    cves = {
        _intelligence_cve(record)
        for record in records
        if _intelligence_cve(record)
    }

    kev = sum(
        1
        for record in records
        if _intelligence_kev(record)
    )

    version_matches = sum(
        1
        for record in records
        if (
            _intelligence_product(record)
            and _intelligence_version(record)
        )
    )

    cpes = {
        _intelligence_cpe(record)
        for record in records
        if _intelligence_cpe(record)
    }

    return {
        "results": len(records),
        "cves": len(cves),
        "kev": kev,
        "version_matches": version_matches,
        "cpes": len(cpes),
    }


def _native_analyzer_counts(
    values: Any,
) -> dict[str, int]:
    """
    Calculate compact native-analyzer execution counters.
    """

    if not values:
        return {
            "runs": 0,
            "successful": 0,
            "failed": 0,
            "findings": 0,
            "errors": 0,
        }

    runs = 0
    successful = 0
    failed = 0
    findings = 0
    errors = 0

    for value in values:
        record = _mapping(value)

        if not record:
            continue

        runs += 1

        if bool(
            record.get(
                "success",
                False,
            )
        ):
            successful += 1
        else:
            failed += 1

        analyzer_findings = record.get(
            "findings",
            [],
        )

        if isinstance(
            analyzer_findings,
            (list, tuple, set),
        ):
            findings += len(analyzer_findings)

        analyzer_errors = record.get(
            "errors",
            [],
        )

        if isinstance(
            analyzer_errors,
            (list, tuple, set),
        ):
            errors += len(analyzer_errors)

    return {
        "runs": runs,
        "successful": successful,
        "failed": failed,
        "findings": findings,
        "errors": errors,
    }


# ----------------------------------------------------------------------
# Assessment Context UI
# ----------------------------------------------------------------------


def assessment_context(
    target: str,
    profile: str,
    authorized: bool,
    tool_count: int,
) -> None:
    """
    Render the compact assessment context after scope authorization.

    This presents the execution context without duplicating the workflow
    tool list or runtime telemetry.
    """

    target_text = str(
        target
    ).strip()

    if not target_text:
        target_text = "UNSPECIFIED"

    profile_text = str(
        profile
    ).strip().upper()

    authorization_text = (
        "✓ AUTHORIZED"
        if authorized
        else "✗ NOT AUTHORIZED"
    )

    authorization_style = (
        "bold green"
        if authorized
        else "bold red"
    )

    tool_text = (
        f"{int(tool_count)} SELECTED"
    )

    table = Table(
        box=box.ROUNDED,
        show_header=False,
        expand=True,
        padding=(0, 1),
    )

    table.add_column(
        "Field",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
        ratio=1,
    )

    table.add_row(
        "Target",
        target_text,
    )

    table.add_row(
        "Profile",
        profile_text,
    )

    table.add_row(
        "Authorization",
        Text(
            authorization_text,
            style=authorization_style,
        ),
    )

    table.add_row(
        "Tools",
        tool_text,
    )

    console.print(
        Panel(
            table,
            title=_ui_panel_title(
                "Assessment Context",
            ),
            border_style="cyan",
            padding=(0, 1),
        )
    )


def assessment_ready() -> None:
    """
    Render the compact transition into assessment execution.
    """

    console.print()

    console.print(
        Text(
            _ui_rule(),
            style="dim",
        )
    )

    console.print(
        Text(
            "ASSESSMENT READY",
            style="bold green",
        )
    )

    console.print(
        Text(
            _ui_rule(),
            style="dim",
        )
    )


# ----------------------------------------------------------------------
# Workflow Execution UI
# ----------------------------------------------------------------------


def workflow_tool_start(
    phase: str,
    tool: str,
    capability: str | None = None,
) -> None:
    """
    Render a compact workflow tool-start event.

    The phase is accepted explicitly so workflow callers can provide the
    complete execution context without constructing terminal formatting
    themselves.
    """

    del phase

    tool_text = str(
        tool
    ).strip()

    capability_text = str(
        capability or "unknown"
    ).strip()

    console.print(
        Text.assemble(
            (
                "  ◉  ",
                "bold cyan",
            ),
            (
                f"{tool_text:<12}",
                "bold",
            ),
            (
                f"{capability_text:<32}",
                "grey70",
            ),
            (
                "RUNNING",
                "bold cyan",
            ),
        )
    )


def workflow_tool_result(
    phase: str,
    tool: str,
    capability: str | None,
    status: str | bool,
) -> None:
    """
    Render a compact workflow tool completion event.

    Supported statuses are:

    - SUCCESS
    - SKIPPED
    - FAILED

    Boolean values remain supported for compatibility with older callers.
    """

    del phase

    tool_text = str(
        tool
    ).strip()

    capability_text = str(
        capability or "unknown"
    ).strip()

    if isinstance(
        status,
        bool,
    ):
        normalized_status = (
            "SUCCESS"
            if status
            else "FAILED"
        )

    else:
        normalized_status = str(
            status
        ).strip().upper()

    if normalized_status == "SUCCESS":
        marker = "✓"
        display_status = "SUCCESS"
        style = "bold green"

    elif normalized_status == "SKIPPED":
        marker = "⊘"
        display_status = "SKIPPED"
        style = "bold grey70"

    else:
        marker = "✗"
        display_status = "FAILED"
        style = "bold red"

    console.print(
        Text.assemble(
            (
                f"  {marker}  ",
                style,
            ),
            (
                f"{tool_text:<12}",
                "bold",
            ),
            (
                f"{capability_text:<32}",
                "grey70",
            ),
            (
                display_status,
                style,
            ),
        )
    )


# ----------------------------------------------------------------------
# Public UI
# ----------------------------------------------------------------------


def banner():
    """
    Render the ScopeForgeX startup identity.

    Assessment-specific information is intentionally kept outside
    the product banner.
    """

    lines = [
        "╭──────────────────────────────────────────────────────────────────────╮",
        "│                                                                      │",
        "│  S C O P E F O R G E X                                               │",
        "│  Security Assessment & Workflow Orchestration                        │",
        "│                                                                      │",
        "│  CLI  •  Security Automation  •  Evidence-Driven Assessment          │",
        "│                                                                      │",
        "╰──────────────────────────────────────────────────────────────────────╯",
    ]

    console.print(
        Text(
            "\n".join(lines),
            style="bold",
        )
    )

    console.print()


def stage(
    title: str,
    color: str = "blue",
):
    """
    Render a consistent workflow-stage header.

    The color parameter remains part of the public API for compatibility
    with existing ScopeForgeX callers.
    """

    del color

    normalized_title = str(
        title
    ).strip()

    if not normalized_title:
        normalized_title = "WORKFLOW"

    console.print()

    console.print(
        Text(
            _ui_rule(),
            style="dim",
        )
    )

    console.print(
        Text(
            normalized_title.upper(),
            style="bold",
        )
    )

    console.print(
        Text(
            _ui_rule(),
            style="dim",
        )
    )


def info(
    message: str,
):
    """
    Render an informational event.
    """

    console.print(
        _ui_status_line(
            "INFO",
            message,
        )
    )


def ok(
    message: str,
):
    """
    Render a successful event.
    """

    console.print(
        _ui_status_line(
            "OK",
            message,
        )
    )


def warn(
    message: str,
):
    """
    Render a warning event.
    """

    console.print(
        _ui_status_line(
            "WARN",
            message,
        )
    )


def err(
    message: str,
):
    """
    Render an error event.
    """

    console.print(
        _ui_status_line(
            "ERROR",
            message,
        )
    )


def summary_table(
    title: str,
    rows: list[tuple[str, str]],
):
    """
    Render a two-column summary table using the ScopeForgeX UI system.
    """

    table = Table(
        title=title,
        show_header=True,
        header_style="bold",
        box=box.ROUNDED,
        expand=True,
    )

    table.add_column(
        "Item",
        style="bold",
        no_wrap=True,
    )

    table.add_column(
        "Value",
        overflow="fold",
        ratio=1,
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


def _finding_panel(
    finding: Mapping[str, Any],
    index: int,
) -> Panel:
    """
    Render one finding as a compact security finding card.
    """

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

    table.add_column(
        "Field",
        style="grey70",
        no_wrap=True,
    )

    table.add_column(
        "Value",
        ratio=1,
    )

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
        table.add_row(
            "CVE",
            cve,
        )

    source = finding.get(
        "source_tool"
    )

    if source:
        table.add_row(
            "Detection",
            str(source),
        )

    return Panel(
        table,
        title=(
            f"{finding_id} — "
            f"{_finding_title(finding)}"
        ),
        border_style={
            "Critical": "red",
            "High": "dark_orange",
            "Medium": "yellow",
            "Low": "green",
            "Informational": "blue",
        }.get(
            severity,
            "grey50",
        ),
        padding=(0, 1),
    )


def _native_analyzer_panel(
    values: Any,
) -> Panel | None:
    """
    Render native analyzer execution coverage.
    """

    counts = _native_analyzer_counts(
        values
    )

    if counts["runs"] == 0:
        return None

    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
    )

    table.add_column(
        "Analyzer Runs",
        justify="center",
    )

    table.add_column(
        "Successful",
        justify="center",
    )

    table.add_column(
        "Failed",
        justify="center",
    )

    table.add_column(
        "Findings",
        justify="center",
    )

    table.add_column(
        "Errors",
        justify="center",
    )

    table.add_row(
        str(counts["runs"]),
        str(counts["successful"]),
        str(counts["failed"]),
        str(counts["findings"]),
        str(counts["errors"]),
    )

    return Panel(
        table,
        title="Native Analysis Coverage",
        subtitle=(
            "Evidence-driven security analyzers"
        ),
        border_style="magenta",
    )


def _vulnerability_intelligence_panel(
    values: Any,
) -> Panel | None:
    """
    Render vulnerability-intelligence coverage and potential exposure.

    Intelligence matches are deliberately presented separately from
    confirmed/normalized security findings.
    """

    records = _intelligence_records(
        values
    )

    if not records:
        return None

    counts = _intelligence_counts(
        records
    )

    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
    )

    table.add_column(
        "Results",
        justify="center",
    )

    table.add_column(
        "CPEs",
        justify="center",
    )

    table.add_column(
        "CVEs",
        justify="center",
    )

    table.add_column(
        "Version Matches",
        justify="center",
    )

    table.add_column(
        "CISA KEV",
        justify="center",
    )

    table.add_row(
        str(counts["results"]),
        str(counts["cpes"]),
        str(counts["cves"]),
        str(counts["version_matches"]),
        str(counts["kev"]),
    )

    return Panel(
        table,
        title="Vulnerability Intelligence",
        subtitle=(
            "NVD/CPE/CVE/KEV — potential exposure, "
            "not confirmed exploitability"
        ),
        border_style="yellow",
    )


def _vulnerability_intelligence_detail_panel(
    values: Any,
) -> Panel | None:
    """
    Render a compact list of individual intelligence matches.

    Only fields defined by the vulnerability-intelligence result model are
    displayed.
    """

    records = _intelligence_records(
        values
    )

    if not records:
        return None

    cve_records = [
        record
        for record in records
        if _intelligence_cve(record)
    ]

    if not cve_records:
        return None

    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
    )

    table.add_column(
        "CVE",
        no_wrap=True,
    )

    table.add_column(
        "Product / Version",
        ratio=1,
    )

    table.add_column(
        "Severity",
        no_wrap=True,
    )

    table.add_column(
        "CVSS",
        justify="center",
        no_wrap=True,
    )

    table.add_column(
        "Asset",
        ratio=1,
    )

    table.add_column(
        "KEV",
        justify="center",
        no_wrap=True,
    )

    for record in cve_records[:8]:
        cve = _intelligence_cve(
            record
        )

        product = _intelligence_product(
            record
        )

        version = _intelligence_version(
            record
        )

        product_text = product or "Unknown"

        if version:
            product_text = (
                f"{product_text} {version}"
            )

        cvss_text = _intelligence_cvss(
            record
        )

        severity = _intelligence_severity(
            record
        )

        kev = (
            "YES"
            if _intelligence_kev(record)
            else "-"
        )

        table.add_row(
            cve,
            product_text,
            Text(
                severity,
                style=_severity_style(
                    severity
                ),
            ),
            cvss_text,
            _intelligence_asset(
                record
            ),
            Text(
                kev,
                style=(
                    "bold red"
                    if kev == "YES"
                    else "grey70"
                ),
            ),
        )

    title = "Potential Vulnerability Matches"

    if len(cve_records) > 8:
        title = (
            "Potential Vulnerability Matches "
            f"— showing 8 of {len(cve_records)}"
        )

    return Panel(
        table,
        title=title,
        subtitle=(
            "Version/CPE intelligence requires "
            "target-specific validation"
        ),
        border_style="yellow",
    )


def assessment_summary(
    ctx: Mapping[str, Any],
) -> None:
    """
    Render the final assessment as a security-first terminal dashboard.

    Operational telemetry remains available below the security result.
    Native analyzer coverage and vulnerability intelligence are displayed
    separately from normalized findings so potential exposure is not
    confused with confirmed security findings.
    """

    findings = [
        _mapping(item)
        for item in (
            ctx.get("findings")
            or []
        )
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
            }.get(
                _finding_severity(item),
                5,
            ),
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
            if counts.get(
                severity,
                0,
            )
        ),
        None,
    )

    risk_text = (
        highest
        or "No Material Finding"
    )

    risk_style = (
        _severity_style(highest)
        if highest
        else "bold green"
    )

    renderables: list[Any] = [
        Panel(
            Text.assemble(
                (
                    "SCOPEFORGEX\n",
                    "bold white",
                ),
                (
                    "Security Assessment Complete",
                    "bold cyan",
                ),
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
        str(
            counts.get(
                "Critical",
                0,
            )
        ),
        str(
            counts.get(
                "High",
                0,
            )
        ),
        str(
            counts.get(
                "Medium",
                0,
            )
        ),
        str(
            counts.get(
                "Low",
                0,
            )
        ),
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
                    else (
                        "Top Findings — "
                        f"showing 8 of {len(findings)}"
                    )
                ),
                border_style="cyan",
            )
        )

    else:
        renderables.append(
            Panel(
                Text(
                    (
                        "No normalized security findings "
                        "were identified by the automated "
                        "assessment."
                    ),
                    style="bold green",
                    justify="center",
                ),
                title="Assessment Result",
                border_style="green",
            )
        )

    native_panel = _native_analyzer_panel(
        ctx.get(
            "native_analyzer_results"
        )
    )

    if native_panel is not None:
        renderables.append(
            native_panel
        )

    intelligence_panel = (
        _vulnerability_intelligence_panel(
            ctx.get(
                "vulnerability_intelligence_results"
            )
        )
    )

    if intelligence_panel is not None:
        renderables.append(
            intelligence_panel
        )

    intelligence_detail_panel = (
        _vulnerability_intelligence_detail_panel(
            ctx.get(
                "vulnerability_intelligence_results"
            )
        )
    )

    if intelligence_detail_panel is not None:
        renderables.append(
            intelligence_detail_panel
        )

    report_paths = (
        ctx.get("report_paths")
        or {}
    )

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
            (
                "Professional",
                "professional_markdown",
            ),
            (
                "Professional HTML",
                "professional_html",
            ),
            (
                "Findings",
                "findings_markdown",
            ),
            (
                "Findings HTML",
                "findings_html",
            ),
            (
                "Canonical JSON",
                "canonical_json",
            ),
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
        ctx.get("execution_results")
        or []
    )

    if execution_results:
        execution_table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
        )

        execution_table.add_column(
            "Tool"
        )

        execution_table.add_column(
            "Status"
        )

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
            ).strip().lower()

            duration = data.get(
                "duration",
                data.get(
                    "duration_seconds",
                    0,
                ),
            )

            try:
                duration_text = (
                    f"{float(duration):.2f}s"
                )

            except (
                TypeError,
                ValueError,
            ):
                duration_text = str(
                    duration
                )

            if status == "success":
                status_text = Text(
                    "SUCCESS",
                    style="bold green",
                )

            elif status == "skipped":
                status_text = Text(
                    "SKIPPED",
                    style="bold grey70",
                )

            else:
                status_text = Text(
                    "FAILED",
                    style="bold red",
                )

            execution_table.add_row(
                str(
                    data.get(
                        "tool",
                        "unknown",
                    )
                ),
                status_text,
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


__all__ = [
    "banner",
    "stage",
    "info",
    "ok",
    "warn",
    "err",
    "summary_table",
    "workflow_tool_start",
    "workflow_tool_result",
    "assessment_context",
    "assessment_ready",
    "assessment_summary",
]
