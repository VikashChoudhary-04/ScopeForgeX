"""
ScopeForgeX — Stage 6 Reporting & Cleanup
=========================================

Final presentation layer for the canonical ScopeForgeX assessment state.

Every completed assessment produces two human-facing report views:

1. Professional Report
   - Structured like a professional security assessment report.
2. Findings-Oriented Report
   - Prioritizes vulnerabilities, misconfigurations, exposures, CVEs,
     affected assets, severity and validation status.

A single canonical JSON report backs both views so presentation can never
silently diverge from the findings produced by the assessment pipeline.

Assessment evidence is preserved; cleanup never deletes raw evidence by
default.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Iterable, Mapping

from reporting import (
    Finding,
    JSONReportExporter,
    ReportData,
    ReportGenerator,
    ScanStatistics,
    StageResult as ReportingStageResult,
)
from scopeforgex.runtime import AssessmentPhase
from scopeforgex.models.adapters import mapping_to_finding
from scopeforgex.ui import err, info, ok, stage, warn


_SEVERITIES = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


_REPORT_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "body",
        "raw_body",
        "raw_header",
        "raw_headers",
        "request",
        "raw_request",
        "response",
        "raw_response",
    }
)


def _sanitize_report_payload(value: Any) -> Any:
    """
    Remove raw HTTP payload material from the published report projection.

    Raw HTTP request/response material remains available to the runtime,
    analyzers, and persisted raw-evidence artifacts. This sanitizer applies
    only to the final report representation so large or sensitive HTTP
    payloads are not duplicated throughout report.json.

    Keys are matched case-insensitively and nested mappings/sequences are
    sanitized recursively. The input object is never mutated.
    """

    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_report_payload(item)
            for key, item in value.items()
            if str(key).lower() not in _REPORT_FORBIDDEN_EVIDENCE_KEYS
        }

    if isinstance(value, (list, tuple, set, frozenset)):
        return [
            _sanitize_report_payload(item)
            for item in value
        ]

    return value


def _serialize(value: Any) -> Any:
    """Convert ScopeForgeX objects into JSON-compatible values."""

    if value is None or isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if isinstance(
        value,
        datetime,
    ):
        return value.isoformat()

    if isinstance(
        value,
        Path,
    ):
        return str(value)

    if hasattr(
        value,
        "as_dict",
    ):
        try:
            return _serialize(
                value.as_dict()
            )
        except Exception:
            pass

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        return [
            _serialize(item)
            for item in value
        ]

    return str(value)


def _as_list(
    value: Any,
) -> list[Any]:
    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        return list(value)

    return [value]


def _mapping(
    value: Any,
) -> dict[str, Any]:
    data = _serialize(value)

    if isinstance(
        data,
        Mapping,
    ):
        return dict(data)

    return {}


def _field(
    value: Any,
    name: str,
    default: Any = None,
) -> Any:
    if isinstance(
        value,
        Mapping,
    ):
        return value.get(
            name,
            default,
        )

    return getattr(
        value,
        name,
        default,
    )


def _tool_results_projection(
    execution_results: Any,
) -> dict[str, str]:
    """
    Build the compact reporting tool-status projection from canonical
    execution results.

    ``execution_results`` may contain ExecutionResult objects or serialized
    mappings. The detailed execution results remain preserved separately in
    ReportData.execution_results.
    """
    result: dict[str, str] = {}

    for execution_result in _as_list(
        execution_results
    ):
        tool = str(
            _field(
                execution_result,
                "tool",
                "",
            )
            or ""
        ).strip()

        if not tool:
            continue

        status = str(
            _field(
                execution_result,
                "status",
                "",
            )
            or ""
        ).strip()

        if not status:
            success = _field(
                execution_result,
                "success",
                False,
            )
            status = (
                "success"
                if success
                else "failed"
            )

        result[tool] = status

    return result


def _finding_id(
    finding: Any,
) -> str:
    return str(
        _field(
            finding,
            "finding_id",
            _field(
                finding,
                "id",
                "",
            ),
        )
        or ""
    )


def _title(
    finding: Any,
) -> str:
    return str(
        _field(
            finding,
            "title",
            "Untitled Finding",
        )
        or "Untitled Finding"
    )


def _severity(
    finding: Any,
) -> str:
    value = str(
        _field(
            finding,
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


def _confidence(
    finding: Any,
) -> str:
    return str(
        _field(
            finding,
            "confidence",
            "Informational",
        )
        or "Informational"
    )


def _status(
    finding: Any,
) -> str:
    return str(
        _field(
            finding,
            "status",
            "Open",
        )
        or "Open"
    )


def _asset(
    finding: Any,
) -> str:
    for name in (
        "url",
        "host",
        "target",
    ):
        value = _field(
            finding,
            name,
        )
        if value:
            return str(value)

    return "Unspecified"


def _source(
    finding: Any,
) -> str:
    return str(
        _field(
            finding,
            "source_tool",
            "ScopeForgeX",
        )
        or "ScopeForgeX"
    )


def _cve(
    finding: Any,
) -> str:
    value = _field(
        finding,
        "cve",
    )

    if value:
        return str(value).strip()

    metadata = _field(
        finding,
        "metadata",
        {},
    )

    if isinstance(
        metadata,
        Mapping,
    ):
        for item in _as_list(
            metadata.get("cves")
        ):
            if str(item).strip():
                return str(item).strip()

    return ""


def _cwes(
    finding: Any,
) -> list[str]:
    values: list[str] = []

    direct = _field(
        finding,
        "cwe",
    )

    if direct:
        values.append(
            str(direct).strip()
        )

    metadata = _field(
        finding,
        "metadata",
        {},
    )

    if isinstance(
        metadata,
        Mapping,
    ):
        values.extend(
            str(item).strip()
            for item in _as_list(
                metadata.get("cwes")
            )
            if str(item).strip()
        )

    result: list[str] = []
    seen: set[str] = set()

    for item in values:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


def _finding_sort_key(
    finding: Any,
) -> tuple[int, str, str]:
    rank = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }

    severity = _severity(
        finding
    )

    return (
        rank.get(
            severity,
            5,
        ),
        _title(
            finding
        ).lower(),
        _finding_id(
            finding,
        ),
    )


def _findings(
    ctx: Mapping[str, Any],
) -> list[Any]:
    findings = list(
        _as_list(
            ctx.get(
                "findings",
                [],
            )
        )
    )

    findings.sort(
        key=_finding_sort_key
    )

    return findings


def _severity_counts(
    findings: Iterable[Any],
) -> dict[str, int]:
    counts = {
        severity: 0
        for severity in _SEVERITIES
    }

    for finding in findings:
        severity = _severity(
            finding
        )

        counts.setdefault(
            severity,
            0,
        )
        counts[severity] += 1

    return counts


def _cves(
    findings: Iterable[Any],
) -> list[str]:
    values: list[str] = []

    for finding in findings:
        cve = _cve(
            finding
        )

        if cve:
            values.append(cve)

    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return sorted(result)


def _assets(
    findings: Iterable[Any],
) -> list[str]:
    values = {
        _asset(finding)
        for finding in findings
    }

    return sorted(
        value
        for value in values
        if value
    )


def _intelligence_summary(
    records: Iterable[Any],
) -> dict[str, int]:
    """Summarize NVD/CVE/KEV intelligence without changing findings."""
    records = list(records)
    cves: set[str] = set()
    kev = 0
    nvd = 0
    version_matches = 0

    for record in records:
        item = _mapping(record)
        if not item:
            continue

        cve = item.get("cve")
        if cve:
            cves.add(str(cve).strip())

        metadata = item.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}

        kev += int(metadata.get("kev") is True)
        nvd += int(
            metadata.get("intelligence_source") == "NVD"
            or item.get("source_tool") == "NVD"
        )
        version_matches += int(
            metadata.get("version_based_match") is True
        )

    return {
        "observations": len(records),
        "cves": len(cves),
        "kev": kev,
        "nvd": nvd,
        "version_matches": version_matches,
    }



def _intelligence_item(
    record: Any,
) -> dict[str, Any]:
    """
    Normalize a vulnerability-intelligence CollectorObservation for reports.

    Intelligence-specific fields are stored partly on the observation itself
    and partly in its metadata. Keep this normalization local to reporting so
    the canonical runtime/intelligence models remain unchanged.
    """

    item = _mapping(
        record
    )

    if not item:
        return {}

    metadata = item.get(
        "metadata",
        {},
    )

    if not isinstance(
        metadata,
        Mapping,
    ):
        metadata = {}

    cwes = metadata.get(
        "cwes"
    )

    if not cwes:
        cwe = item.get(
            "cwe"
        )

        cwes = (
            [cwe]
            if cwe
            else []
        )

    cve = (
        item.get("cve")
        or item.get("value")
        or "-"
    )

    title = str(
        item.get("title")
        or "-"
    ).strip()

    if (
        cve != "-"
        and title.startswith(f"{cve}:")
    ):
        title = title[len(cve) + 1:].strip()

    return {
        "cve": str(cve).strip(),
        "title": title,
        "description": str(
            item.get("description")
            or ""
        ).strip(),
        "product": str(
            metadata.get("product")
            or "-"
        ).strip(),
        "version": str(
            metadata.get("version")
            or "-"
        ).strip(),
        "cpe": str(
            metadata.get("cpe")
            or "-"
        ).strip(),
        "severity": str(
            item.get("severity")
            or "Informational"
        ).strip(),
        "cvss_score": metadata.get(
            "cvss_score"
        ),
        "cvss_version": str(
            metadata.get("cvss_version")
            or "-"
        ).strip(),
        "target": str(
            item.get("target")
            or ""
        ).strip(),
        "host": str(
            item.get("host")
            or ""
        ).strip(),
        "port": item.get(
            "port"
        ),
        "url": str(
            item.get("url")
            or ""
        ).strip(),
        "kev": (
            metadata.get("kev")
            is True
        ),
        "kev_date_added": str(
            metadata.get(
                "kev_date_added"
            )
            or "-"
        ).strip(),
        "kev_due_date": str(
            metadata.get(
                "kev_due_date"
            )
            or "-"
        ).strip(),
        "kev_ransomware_use": metadata.get(
            "kev_ransomware_use"
        ),
        "cwes": cwes,
        "references": item.get(
            "references"
        ) or [],
        "validation_status": str(
            metadata.get(
                "validation_status"
            )
            or item.get("status")
            or "Pending"
        ).strip(),
        "source_tool": str(
            item.get("source_tool")
            or metadata.get("source_tool")
            or "NVD"
        ).strip(),
        "detection_method": str(
            item.get("detection_method")
            or metadata.get(
                "source_detection_method"
            )
            or "-"
        ).strip(),
    }


def _intelligence_markdown(
    records: Iterable[Any],
) -> list[str]:
    """Render detailed NVD/CVE/KEV intelligence records."""

    rows: list[str] = []

    for record in records:
        item = _intelligence_item(
            record
        )

        if not item:
            continue

        product = item["product"]
        version = item["version"]
        cpe = item["cpe"]
        cve = item["cve"]
        title = item["title"]
        severity = item["severity"]

        cvss_score = item["cvss_score"]
        cvss_version = item["cvss_version"]

        if cvss_score is None:
            cvss = "-"
        else:
            cvss = (
                f"{cvss_score} "
                f"({cvss_version})"
            )

        target = (
            item["target"]
            or item["host"]
            or "-"
        )

        port = item["port"]

        if port is not None:
            target = f"{target}:{port}"

        url = item["url"]

        if url:
            target = (
                f"{target} — {url}"
            )

        kev = (
            "Yes"
            if item["kev"]
            else "No"
        )

        kev_added = item[
            "kev_date_added"
        ]

        kev_due = item[
            "kev_due_date"
        ]

        ransomware = item[
            "kev_ransomware_use"
        ]

        if ransomware is True:
            ransomware_text = "Yes"
        elif ransomware is False:
            ransomware_text = "No"
        else:
            ransomware_text = "-"

        cwes = item["cwes"]

        if isinstance(
            cwes,
            (list, tuple, set),
        ):
            cwe_text = ", ".join(
                str(value).strip()
                for value in cwes
                if str(value).strip()
            ) or "-"
        else:
            cwe_text = (
                str(cwes).strip()
                or "-"
            )

        rows.append(
            "| "
            f"{product} {version} | "
            f"{cpe} | "
            f"{cve} — {title} | "
            f"{severity} | "
            f"{cvss} | "
            f"{target} | "
            f"{kev} | "
            f"{kev_added} | "
            f"{kev_due} | "
            f"{ransomware_text} | "
            f"{cwe_text} |"
        )

    if not rows:
        return []

    return [
        "### Intelligence Matches",
        "",
        "| Product / Version | CPE | CVE / Title | Severity | CVSS | Asset | KEV | KEV Added | KEV Due | Ransomware | CWE |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
        *rows,
        "",
    ]



def _highest_severity(
    findings: Iterable[Any],
) -> str:
    counts = _severity_counts(
        findings
    )

    for severity in _SEVERITIES:
        if counts.get(
            severity,
            0,
        ):
            return severity

    return "No Material Finding"


def _duration_seconds(
    ctx: Mapping[str, Any],
) -> float:
    value = ctx.get(
        "workflow_duration"
    )

    if isinstance(
        value,
        (int, float),
    ):
        return float(value)

    start = ctx.get(
        "workflow_start_time"
    )
    end = ctx.get(
        "workflow_end_time"
    )

    if isinstance(
        start,
        (int, float),
    ) and isinstance(
        end,
        (int, float),
    ):
        return max(
            0.0,
            float(end) - float(start),
        )

    return 0.0


def _format_timestamp(value: Any) -> str:
    """Return a human-readable UTC timestamp while preserving raw values."""

    if value is None or value == "":
        return "-"

    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            return str(value)

    text = str(value).strip()
    if not text:
        return "-"

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return text


def _iter_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    """Yield nested mappings from report/runtime data."""

    if isinstance(value, Mapping):
        yield value
        for item in value.values():
            yield from _iter_mappings(item)
        return

    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_mappings(item)


def _observation_records(ctx: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Collect serialized observation mappings from collector/analyzer data."""

    records: list[Mapping[str, Any]] = []
    seen: set[int] = set()

    sources = (
        ctx.get("collector_results", []),
        ctx.get("native_analyzer_results", []),
    )

    for source in sources:
        for item in _iter_mappings(_serialize(source)):
            if "observation_type" in item or "observations" in item:
                marker = id(item)
                if marker not in seen:
                    seen.add(marker)
                    records.append(item)

            observations = item.get("observations")
            if isinstance(observations, list):
                for observation in observations:
                    if isinstance(observation, Mapping):
                        records.append(observation)

    return records


def _observation_type_value(item: Mapping[str, Any]) -> str:
    """Return a normalized observation type from a serialized record."""

    return str(
        item.get(
            "observation_type",
            item.get("type", ""),
        )
        or ""
    ).strip().upper()


def _observation_host(item: Mapping[str, Any]) -> str:
    """Return a normalized host-like value from an observation."""

    for key in ("host", "hostname", "ip", "target"):
        value = item.get(key)
        if value:
            return str(value).strip()
    return ""


def _observation_url(item: Mapping[str, Any]) -> str:
    """Return a normalized URL-like value from an observation."""

    for key in ("url", "endpoint", "route"):
        value = item.get(key)
        if value and str(value).startswith(("http://", "https://")):
            return str(value).strip()
    return ""


def _attack_surface_statistics(ctx: Mapping[str, Any]) -> dict[str, int]:
    """Derive attack-surface counts from retained collector observations."""

    records = _observation_records(ctx)

    subdomains: set[str] = set()
    alive_hosts: set[str] = set()
    final_hosts: set[str] = set()
    urls: set[str] = set()

    for item in records:
        observation_type = _observation_type_value(item)
        host = _observation_host(item)
        url = _observation_url(item)

        if observation_type in {"SUBDOMAIN", "SUBDOMAIN_DISCOVERY"}:
            if host:
                subdomains.add(host)

        if observation_type in {
            "HOST_UP",
            "HTTP_SERVICE",
            "HTTP_STATUS",
        }:
            if host:
                alive_hosts.add(host)

        if host and observation_type in {
            "HOST",
            "HOST_UP",
            "HOST_DISCOVERY",
            "HTTP_SERVICE",
            "HTTP_STATUS",
            "OPEN_PORT",
            "SERVICE",
            "SERVICE_VERSION",
        }:
            final_hosts.add(host)

        if observation_type in {
            "URL",
            "ENDPOINT",
            "API_ENDPOINT",
            "API_ROUTE",
            "ROUTE",
        } and url:
            urls.add(url)

    return {
        "subdomains_found": len(subdomains),
        "alive_hosts": len(alive_hosts),
        "final_hosts": len(final_hosts),
        "urls_discovered": len(urls),
        "attack_surface_observations": len(records),
    }


def _evidence_reference_entries(
    ctx: Mapping[str, Any],
    findings: Iterable[Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build report evidence references from evidence already attached to data."""

    finding_refs: list[dict[str, Any]] = []
    raw_refs: list[dict[str, Any]] = []
    general_refs: list[dict[str, Any]] = []

    for finding in findings:
        evidence = _field(finding, "evidence", None)
        if evidence in (None, "", [], {}, (), set(), frozenset()):
            continue

        entry = {
            "finding_id": _finding_id(finding),
            "source_tool": _source(finding),
            "evidence": _serialize(evidence),
        }
        finding_refs.append(entry)
        general_refs.append(entry)

    def walk_raw(value: Any, source: str = "") -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                key_text = str(key).lower()
                if any(
                    marker in key_text
                    for marker in (
                        "raw_evidence",
                        "evidence_path",
                        "raw_output_path",
                        "output_path",
                        "artifact_path",
                    )
                ) and item not in (None, "", [], {}, (), set(), frozenset()):
                    raw_refs.append(
                        {
                            "source": source or "assessment",
                            "field": str(key),
                            "reference": _serialize(item),
                        }
                    )
                walk_raw(item, source)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                walk_raw(item, source)

    for key in ("collector_results", "execution_results"):
        walk_raw(
            ctx.get(key, []),
            key,
        )

    # Deduplicate references by their serialized representation without
    # changing the evidence payload supplied by the runtime.
    def unique(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in entries:
            marker = json.dumps(
                _serialize(entry),
                sort_keys=True,
                ensure_ascii=False,
            )
            if marker not in seen:
                seen.add(marker)
                result.append(entry)
        return result

    finding_refs = unique(finding_refs)
    raw_refs = unique(raw_refs)
    general_refs = unique([*general_refs, *raw_refs])

    return general_refs, raw_refs, finding_refs


def _generated_paths(
    outdir: Path,
) -> dict[str, Path]:
    report_dir = outdir / "report"

    return {
        "professional_markdown": (
            report_dir / "professional.md"
        ),
        "professional_html": (
            report_dir / "professional.html"
        ),
        "findings_markdown": (
            report_dir / "findings.md"
        ),
        "findings_html": (
            report_dir / "findings.html"
        ),
        "canonical_json": (
            report_dir / "report.json"
        ),
        "markdown": (
            outdir / "report.md"
        ),
        "findings": (
            outdir / "findings.md"
        ),
        "json": (
            outdir / "report.json"
        ),
    }


def _report_state(
    ctx: dict[str, Any],
    paths: Mapping[str, Path],
) -> dict[str, Any]:
    findings = _findings(
        ctx
    )

    statistics = _serialize(
        ctx.get(
            "statistics",
            {},
        )
    )

    if not isinstance(
        statistics,
        Mapping,
    ):
        statistics = {}

    statistics = dict(statistics)

    # Derive report-level execution and finding statistics from the structured
    # workflow state retained in the context. Runtime statistics may contain
    # stale zero values, so these canonical report metrics must be derived from
    # the actual execution/stage/finding collections rather than preserved via
    # setdefault().
    derived_statistics = _attack_surface_statistics(ctx)
    statistics.update(derived_statistics)

    execution_results = _as_list(
        ctx.get(
            "execution_results",
            [],
        )
    )

    stage_results = _as_list(
        ctx.get(
            "stage_results",
            [],
        )
    )

    statistics["tools_executed"] = len(
        execution_results
    )

    stages_executed = 0
    stages_skipped = 0

    for stage_result in stage_results:
        status = str(
            _field(
                stage_result,
                "status",
                "",
            )
            or ""
        ).strip().lower()

        if status == "skipped":
            stages_skipped += 1
            continue

        if status:
            stages_executed += 1

    statistics["stages_executed"] = stages_executed
    statistics["stages_skipped"] = stages_skipped

    statistics["findings_total"] = len(
        findings
    )

    severity_counts = _severity_counts(
        findings
    )

    statistics["findings_critical"] = severity_counts.get(
        "Critical",
        0,
    )
    statistics["findings_high"] = severity_counts.get(
        "High",
        0,
    )
    statistics["findings_medium"] = severity_counts.get(
        "Medium",
        0,
    )
    statistics["findings_low"] = severity_counts.get(
        "Low",
        0,
    )
    statistics["findings_informational"] = severity_counts.get(
        "Informational",
        0,
    )

    status_counts = Counter(
        _status(finding).strip().lower()
        for finding in findings
    )

    statistics["findings_confirmed"] = status_counts.get(
        "confirmed",
        0,
    )
    statistics["findings_pending"] = status_counts.get(
        "pending",
        0,
    )
    statistics["findings_false_positive"] = status_counts.get(
        "false positive",
        0,
    ) + status_counts.get(
        "false_positive",
        0,
    )

    pipeline_metadata = _mapping(
        ctx.get("analysis_metadata", {})
    )
    for key in (
        "input_observation_count",
        "attack_surface_observation_count",
        "final_finding_count",
        "duplicate_count",
        "processing_error_count",
        "correlation_group_count",
        "evidence_bearing_finding_count",
        "findings_without_evidence_count",
    ):
        if key in pipeline_metadata:
            statistics.setdefault(
                key,
                pipeline_metadata[key],
            )

    start_time = ctx.get(
        "workflow_start_time"
    )

    end_time = ctx.get(
        "workflow_end_time"
    )

    duration = _duration_seconds(
        ctx
    )

    generated_files = [
        str(path)
        for path in paths.values()
    ]

    # Keep existing assessment artifacts in addition to report outputs.
    existing_files = [
        str(item)
        for item in _as_list(
            ctx.get(
                "generated_files",
                [],
            )
        )
        if str(item)
    ]

    generated_files = list(
        dict.fromkeys(
            [
                *existing_files,
                *generated_files,
            ]
        )
    )

    statistics["files_generated"] = len(
        generated_files
    )

    existing_evidence = _as_list(
        ctx.get("evidence_references", [])
    )
    existing_raw_evidence = _as_list(
        ctx.get("raw_evidence_references", [])
    )
    existing_finding_evidence = _as_list(
        ctx.get("finding_evidence_references", [])
    )

    derived_evidence, derived_raw_evidence, derived_finding_evidence = (
        _evidence_reference_entries(
            ctx,
            findings,
        )
    )

    def unique_serialized_entries(values: Iterable[Any]) -> list[Any]:
        """Deduplicate JSON-compatible entries without hashing mappings."""

        result: list[Any] = []
        seen: set[str] = set()

        for value in values:
            serialized = _serialize(value)
            marker = json.dumps(
                serialized,
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            if marker in seen:
                continue
            seen.add(marker)
            result.append(serialized)

        return result

    evidence_references = unique_serialized_entries(
        [
            *existing_evidence,
            *derived_evidence,
        ]
    )
    raw_evidence_references = unique_serialized_entries(
        [
            *existing_raw_evidence,
            *derived_raw_evidence,
        ]
    )
    finding_evidence_references = unique_serialized_entries(
        [
            *existing_finding_evidence,
            *derived_finding_evidence,
        ]
    )

    existing_correlated_evidence = _as_list(
        ctx.get("correlated_evidence_references", [])
    )

    start_time_display = _format_timestamp(start_time)
    end_time_display = _format_timestamp(end_time)

    return {
        "schema_version": "4.0",
        "generator": "ScopeForgeX",
        "generator_version": "3.0.0",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": str(
            ctx.get(
                "target",
                "",
            )
            or ""
        ),
        "target_type": str(
            ctx.get(
                "target_type",
                "",
            )
            or ""
        ),
        "profile": str(
            ctx.get(
                "profile",
                "",
            )
            or ""
        ),
        "run_id": str(
            ctx.get(
                "run_id",
                "",
            )
            or ""
        ),
        "start_time": start_time,
        "end_time": end_time,
        "start_time_display": start_time_display,
        "end_time_display": end_time_display,
        "duration": duration,
        "workflow_start_time": start_time,
        "workflow_end_time": end_time,
        "workflow_duration": duration,
        "findings": [
            _serialize(item)
            for item in findings
        ],
        "correlation_groups": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "correlation_groups",
                    [],
                )
            )
        ],
        "correlated_findings": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "correlated_findings",
                    [],
                )
            )
        ],
        "collector_results": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "collector_results",
                    [],
                )
            )
        ],
        "execution_results": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "execution_results",
                    [],
                )
            )
        ],
        "native_analyzer_results": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "native_analyzer_results",
                    [],
                )
            )
        ],
        "vulnerability_intelligence_results": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "vulnerability_intelligence_results",
                    [],
                )
            )
        ],
        "software_assessments": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "software_assessments",
                    [],
                )
            )
        ],
        "stage_results": [
            _serialize(item)
            for item in _as_list(
                ctx.get(
                    "stage_results",
                    [],
                )
            )
        ],
        "evidence_references": evidence_references,
        "raw_evidence_references": raw_evidence_references,
        "finding_evidence_references": finding_evidence_references,
        "correlated_evidence_references": [
            _serialize(item)
            for item in existing_correlated_evidence
        ],
        "warnings": [
            str(item)
            for item in _as_list(
                ctx.get(
                    "warnings",
                    [],
                )
            )
        ],
        "errors": [
            str(item)
            for item in _as_list(
                ctx.get(
                    "errors",
                    [],
                )
            )
        ],
        "generated_files": generated_files,
        "statistics": dict(
            statistics
        ),
        "summary": {
            "total_findings": len(findings),
            "severity": _severity_counts(
                findings
            ),
            "highest_severity": _highest_severity(
                findings
            ),
            "cve_count": len(
                _cves(findings)
            ),
            "cves": _cves(findings),
            "affected_asset_count": len(
                _assets(findings)
            ),
            "affected_assets": _assets(findings),
            "attack_surface_observation_count": statistics.get(
                "attack_surface_observations",
                statistics.get(
                    "attack_surface_observation_count",
                    0,
                ),
            ),
            "evidence_bearing_finding_count": len(
                finding_evidence_references
            ),
        },
        "vulnerability_intelligence": _intelligence_summary(
            _as_list(
                ctx.get(
                    "vulnerability_intelligence_results",
                    [],
                )
            )
        ),
        "analysis_metadata": _mapping(
            ctx.get("analysis_metadata", {})
        ),
        "report_views": {
            "professional": {
                "markdown": "report/professional.md",
                "html": "report/professional.html",
            },
            "findings": {
                "markdown": "report/findings.md",
                "html": "report/findings.html",
            },
            "canonical_json": "report/report.json",
            "compatibility": {
                "markdown": "report.md",
                "findings_markdown": "findings.md",
                "json": "report.json",
            },
        },
    }


def _json_block(
    value: Any,
) -> str:
    return json.dumps(
        _serialize(value),
        indent=2,
        ensure_ascii=False,
    )


def _finding_markdown(
    finding: Any,
    index: int,
) -> str:
    finding_id = (
        _finding_id(finding)
        or f"SF-{index:03d}"
    )

    lines = [
        f"### {finding_id} — {_title(finding)}",
        "",
        "| Severity | Confidence | Validation | Source |",
        "|---|---|---|---|",
        (
            f"| **{_severity(finding)}** | "
            f"{_confidence(finding)} | "
            f"{_status(finding)} | "
            f"{_source(finding)} |"
        ),
        "",
        f"**Affected Asset:** `{_asset(finding)}`",
        "",
    ]

    cve = _cve(
        finding
    )
    if cve:
        lines.extend(
            [
                f"**CVE:** `{cve}`",
                "",
            ]
        )

    cwes = _cwes(
        finding
    )
    if cwes:
        lines.extend(
            [
                f"**CWE:** "
                + ", ".join(
                    f"`{item}`"
                    for item in cwes
                ),
                "",
            ]
        )

    for heading, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Remediation", "remediation"),
    ):
        value = _field(
            finding,
            key,
            "",
        )

        if not value:
            continue

        lines.extend(
            [
                f"**{heading}**",
                "",
                str(value),
                "",
            ]
        )

    evidence = _field(
        finding,
        "evidence",
        "",
    )

    if evidence:
        lines.extend(
            [
                "**Evidence**",
                "",
                "```json",
                _json_block(evidence),
                "```",
                "",
            ]
        )

    detection = _field(
        finding,
        "detection_method",
        "",
    )

    if detection:
        lines.extend(
            [
                f"**Detection:** {detection}",
                "",
            ]
        )

    references = _field(
        finding,
        "references",
        [],
    )

    reference_list = _as_list(
        references
    )

    if reference_list:
        lines.extend(
            [
                "**References**",
                "",
            ]
        )

        for reference in reference_list:
            lines.append(
                f"- {reference}"
            )

        lines.append("")

    return "\n".join(
        lines
    )


def _professional_markdown(
    data: Mapping[str, Any],
) -> str:
    findings = list(
        data.get(
            "findings",
            [],
        )
    )

    findings.sort(
        key=_finding_sort_key
    )

    counts = _severity_counts(
        findings
    )

    cves = _cves(
        findings
    )

    assets = _assets(
        findings
    )

    risk = _highest_severity(
        findings
    )

    duration = data.get(
        "duration",
        0.0,
    )

    try:
        duration_text = (
            f"{float(duration):.2f} seconds"
        )
    except (
        TypeError,
        ValueError,
    ):
        duration_text = str(
            duration
        )

    lines = [
        "# ScopeForgeX Security Assessment Report",
        "",
        "> Professional assessment view generated from the canonical "
        "ScopeForgeX assessment state.",
        "",
        "## 1. Executive Summary",
        "",
    ]

    if findings:
        lines.append(
            f"The assessment identified **{len(findings)}** normalized "
            f"finding(s). The highest observed severity is **{risk}**."
        )
    else:
        lines.append(
            "No vulnerabilities, misconfigurations or other security "
            "findings were recorded by the automated assessment."
        )

    lines.extend(
        [
            "",
            f"- **Target:** `{data.get('target', '-')}`",
            f"- **Target Type:** `{data.get('target_type', '-')}`",
            f"- **Profile:** `{data.get('profile', '-')}`",
            f"- **Run ID:** `{data.get('run_id', '-')}`",
            f"- **Duration:** `{duration_text}`",
            "",
            "### Risk Summary",
            "",
            "| Severity | Findings |",
            "|---|---:|",
        ]
    )

    for severity in _SEVERITIES:
        lines.append(
            f"| {severity} | {counts.get(severity, 0)} |"
        )

    lines.extend(
        [
            "",
            f"- **CVEs identified:** {len(cves)}",
            f"- **Affected assets:** {len(assets)}",
            f"- **Correlation groups:** "
            f"{len(data.get('correlation_groups', []))}",
            "",
            "## Vulnerability Intelligence",
            "",
            "NVD/CPE/CVE intelligence identifies potential exposure from observed software identity. Version-based matches remain pending target-specific validation and do not by themselves confirm exploitability.",
            "",
            f"- **NVD intelligence observations:** {data.get('vulnerability_intelligence', {}).get('nvd', 0)}",
            f"- **CVE intelligence matches:** {data.get('vulnerability_intelligence', {}).get('cves', 0)}",
            f"- **Version-based matches:** {data.get('vulnerability_intelligence', {}).get('version_matches', 0)}",
            f"- **CISA KEV matches:** {data.get('vulnerability_intelligence', {}).get('kev', 0)}",
            "",
        ]
    )

    intelligence_records = data.get(
        "vulnerability_intelligence_results",
        [],
    )

    lines.extend(
        _intelligence_markdown(
            intelligence_records,
        )
    )

    lines.extend(
        [
            "## 2. Assessment Scope",
            "",
            f"- Target: `{data.get('target', '-')}`",
            f"- Target type: `{data.get('target_type', '-')}`",
            f"- Profile: `{data.get('profile', '-')}`",
            f"- Start time: `{data.get('start_time_display', data.get('start_time', '-'))}`",
            f"- End time: `{data.get('end_time_display', data.get('end_time', '-'))}`",
            "",
            "## 3. Rules of Engagement / Limitations",
            "",
            "- Execution is governed by the explicit authorization and scope "
            "supplied to ScopeForgeX.",
            "- Automated detection is not equivalent to manual validation.",
            "- Absence of findings is not proof that the target is secure.",
            "",
            "## 4. Methodology",
            "",
            "1. Scope & Authorization",
            "2. Reconnaissance",
            "3. Enumeration",
            "4. Vulnerability Assessment",
            "5. Vulnerability Validation",
            "6. Authentication / Credential Assessment",
            "7. Reporting",
            "",
            "## 5. Attack Surface Summary",
            "",
            f"- **Subdomains discovered:** "
            f"{data.get('statistics', {}).get('subdomains_found', 0)}",
            f"- **Alive hosts:** "
            f"{data.get('statistics', {}).get('alive_hosts', 0)}",
            f"- **Final hosts:** "
            f"{data.get('statistics', {}).get('final_hosts', 0)}",
            f"- **URLs discovered:** "
            f"{data.get('statistics', {}).get('urls_discovered', 0)}",
            "",
            "## 6. Risk Summary",
            "",
            f"**Highest observed severity:** **{risk}**",
            "",
            "Finding severity and confidence are separate attributes. "
            "The severity represents assessed impact, while confidence "
            "represents the strength of the available evidence.",
            "",
            "## 7. Findings",
            "",
        ]
    )

    if findings:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            lines.append(
                _finding_markdown(
                    finding,
                    index,
                )
            )
            lines.append("")
    else:
        lines.extend(
            [
                "No findings were recorded by the canonical analysis pipeline.",
                "",
            ]
        )

    lines.extend(
        [
            "## 8. Technical Evidence",
            "",
            "Original tool output and collected evidence remain preserved "
            "in the assessment artifact directory. Canonical finding "
            "evidence is embedded with each finding when available.",
            "",
            f"- **Evidence references:** "
            f"{len(data.get('evidence_references', []))}",
            f"- **Finding evidence references:** "
            f"{len(data.get('finding_evidence_references', []))}",
            f"- **Correlated evidence references:** "
            f"{len(data.get('correlated_evidence_references', []))}",
            "",
            "## 9. Impact",
            "",
            "Impact is documented per finding. Correlated observations should "
            "be considered together where they describe the same affected "
            "asset or attack surface.",
            "",
            "## 10. Remediation",
            "",
            "Finding-specific remediation guidance is recorded with each "
            "finding. Prioritize remediation using severity, confidence, "
            "asset criticality and validation status.",
            "",
            "## 11. Validation Status",
            "",
            "| Status | Findings |",
            "|---|---:|",
        ]
    )

    status_counts = Counter(
        _status(finding)
        for finding in findings
    )

    if status_counts:
        for status, count in sorted(
            status_counts.items(),
            key=lambda item: item[0].lower(),
        ):
            lines.append(
                f"| {status} | {count} |"
            )
    else:
        lines.append(
            "| None recorded | 0 |"
        )

    lines.extend(
        [
            "",
            "## 12. Tool Coverage",
            "",
            "| Tool | Status |",
            "|---|---|",
        ]
    )

    for result in data.get(
        "execution_results",
        [],
    ):
        item = _mapping(
            result
        )

        tool = item.get(
            "tool",
            "unknown",
        )

        status = item.get(
            "status",
            "unknown",
        )

        lines.append(
            f"| {tool} | `{status}` |"
        )

    lines.extend(
        [
            "",
            "## 13. Native ScopeForgeX Analysis",
            "",
            "| Analyzer | Results | Findings |",
            "|---|---:|---:|",
        ]
    )

    native_summary: dict[str, list[int]] = {}

    for result in data.get(
        "native_analyzer_results",
        [],
    ):
        item = _mapping(
            result
        )

        analyzer = str(
            item.get(
                "analyzer",
                "unknown",
            )
        )

        native_summary.setdefault(
            analyzer,
            [0, 0],
        )

        native_summary[analyzer][0] += 1
        native_summary[analyzer][1] += len(
            _as_list(
                item.get(
                    "findings",
                    [],
                )
            )
        )

    if native_summary:
        for analyzer in sorted(
            native_summary
        ):
            results_count, findings_count = (
                native_summary[analyzer]
            )

            lines.append(
                f"| {analyzer} | "
                f"{results_count} | "
                f"{findings_count} |"
            )
    else:
        lines.append(
            "| None recorded | 0 | 0 |"
        )

    lines.extend(
        [
            "",
            "## 14. Appendix",
            "",
            f"- Execution results: "
            f"{len(data.get('execution_results', []))}",
            f"- Collector results: "
            f"{len(data.get('collector_results', []))}",
            f"- Native analyzer results: "
            f"{len(data.get('native_analyzer_results', []))}",
            f"- Vulnerability intelligence results: "
            f"{len(data.get('vulnerability_intelligence_results', []))}",
            f"- Warnings: "
            f"{len(data.get('warnings', []))}",
            f"- Errors: "
            f"{len(data.get('errors', []))}",
            "",
        ]
    )

    return "\n".join(
        lines
    ).rstrip() + "\n"


def _findings_markdown(
    data: Mapping[str, Any],
) -> str:
    findings = list(
        data.get(
            "findings",
            [],
        )
    )

    findings.sort(
        key=_finding_sort_key
    )

    counts = _severity_counts(
        findings
    )

    cves = _cves(
        findings
    )

    assets = _assets(
        findings
    )

    lines = [
        "# ScopeForgeX Findings Report",
        "",
        "> Findings-oriented view. Security findings are presented before "
        "workflow telemetry.",
        "",
        "## Findings Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total findings | **{len(findings)}** |",
        f"| Critical | **{counts.get('Critical', 0)}** |",
        f"| High | **{counts.get('High', 0)}** |",
        f"| Medium | **{counts.get('Medium', 0)}** |",
        f"| Low | **{counts.get('Low', 0)}** |",
        f"| Informational | **{counts.get('Informational', 0)}** |",
        f"| CVEs | **{len(cves)}** |",
        f"| Affected assets | **{len(assets)}** |",
        f"| Evidence-backed findings | **{len(data.get('finding_evidence_references', []))}** |",
        f"| NVD matches | **{data.get('vulnerability_intelligence', {}).get('nvd', 0)}** |",
        f"| CISA KEV matches | **{data.get('vulnerability_intelligence', {}).get('kev', 0)}** |",
        "",
        "## Vulnerability Intelligence",
        "",
        "Version-based intelligence represents potential exposure until target-specific validation is completed.",
        "",
        f"- **NVD intelligence observations:** {data.get('vulnerability_intelligence', {}).get('nvd', 0)}",
        f"- **CVE intelligence matches:** {data.get('vulnerability_intelligence', {}).get('cves', 0)}",
        f"- **Version-based matches:** {data.get('vulnerability_intelligence', {}).get('version_matches', 0)}",
        f"- **CISA KEV matches:** {data.get('vulnerability_intelligence', {}).get('kev', 0)}",
        "",
    ]

    intelligence_records = data.get(
        "vulnerability_intelligence_results",
        [],
    )

    lines.extend(
        _intelligence_markdown(
            intelligence_records,
        )
    )

    lines.extend(
        [
            "## Findings",
            "",
        ]
    )

    if findings:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            lines.append(
                _finding_markdown(
                    finding,
                    index,
                )
            )
            lines.append("")
    else:
        lines.extend(
            [
                "No vulnerabilities, misconfigurations, exposed resources "
                "or CVE-associated findings were recorded.",
                "",
            ]
        )

    lines.extend(
        [
            "## CVE Summary",
            "",
        ]
    )

    if cves:
        lines.extend(
            [
                "| CVE | Severity | Finding | Asset | Source |",
                "|---|---|---|---|---|",
            ]
        )

        for finding in findings:
            cve = _cve(
                finding
            )

            if not cve:
                continue

            lines.append(
                f"| `{cve}` | "
                f"{_severity(finding)} | "
                f"`{_finding_id(finding)}` | "
                f"`{_asset(finding)}` | "
                f"{_source(finding)} |"
            )
    else:
        lines.append(
            "No CVEs were identified."
        )

    lines.extend(
        [
            "",
            "## Affected Assets",
            "",
        ]
    )

    if assets:
        asset_counts = Counter(
            _asset(finding)
            for finding in findings
        )

        lines.extend(
            [
                "| Asset | Findings |",
                "|---|---:|",
            ]
        )

        for asset in assets:
            lines.append(
                f"| `{asset}` | "
                f"{asset_counts[asset]} |"
            )
    else:
        lines.append(
            "No affected assets were associated with final findings."
        )

    lines.extend(
        [
            "",
            "## Finding Sources",
            "",
            "| Source | Findings |",
            "|---|---:|",
        ]
    )

    sources = Counter(
        _source(finding)
        for finding in findings
    )

    if sources:
        for source, count in sorted(
            sources.items(),
            key=lambda item: item[0].lower(),
        ):
            lines.append(
                f"| {source} | {count} |"
            )
    else:
        lines.append(
            "| No findings | 0 |"
        )

    lines.extend(
        [
            "",
            "## Assessment Context",
            "",
            f"- **Target:** `{data.get('target', '-')}`",
            f"- **Profile:** `{data.get('profile', '-')}`",
            f"- **Run ID:** `{data.get('run_id', '-')}`",
            "",
        ]
    )

    return "\n".join(
        lines
    ).rstrip() + "\n"


_HTML_CSS = """
:root {
  color-scheme: dark;
  --bg: #08111f;
  --panel: #101b2d;
  --panel2: #16243a;
  --text: #edf4ff;
  --muted: #9eacc2;
  --border: #2b3d59;
  --accent: #63b3ff;
  --critical: #ff5f6d;
  --high: #ff9d45;
  --medium: #ffd166;
  --low: #75d69a;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: linear-gradient(135deg, #07101c, #0b1424);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system,
    BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.55;
}
main {
  max-width: 1180px;
  margin: 0 auto;
  padding: 48px 24px 80px;
}
header { margin-bottom: 28px; }
h1 { margin: 0 0 8px; font-size: 2.4rem; letter-spacing: -.035em; }
h2 { margin-top: 38px; }
h3 { margin-top: 26px; }
.meta { color: var(--muted); }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
  gap: 14px;
  margin: 22px 0;
}
.card, .finding {
  background: rgba(16, 27, 45, .92);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 20px;
}
.metric { font-size: 2rem; font-weight: 800; }
.label {
  color: var(--muted);
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .08em;
}
.finding { margin: 18px 0; }
.badge {
  display: inline-block;
  padding: 4px 9px;
  border-radius: 999px;
  font-size: .78rem;
  font-weight: 800;
  margin: 0 6px 6px 0;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 14px 0 26px;
}
th, td {
  padding: 11px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
}
th {
  color: var(--muted);
  font-size: .78rem;
  text-transform: uppercase;
  letter-spacing: .05em;
}
code {
  background: var(--panel2);
  padding: 2px 6px;
  border-radius: 6px;
}
pre {
  overflow-x: auto;
  background: #050b14;
  border: 1px solid var(--border);
  padding: 16px;
  border-radius: 12px;
}
.small { color: var(--muted); }
"""


def _html_finding(
    finding: Any,
    index: int,
) -> str:
    finding_id = (
        _finding_id(finding)
        or f"SF-{index:03d}"
    )

    severity = _severity(
        finding
    )

    color = {
        "Critical": "var(--critical)",
        "High": "var(--high)",
        "Medium": "var(--medium)",
        "Low": "var(--low)",
        "Informational": "var(--accent)",
    }.get(
        severity,
        "var(--accent)",
    )

    cve = _cve(
        finding
    )

    parts = [
        '<article class="finding">',
        f"<h2>{escape(finding_id)} — "
        f"{escape(_title(finding))}</h2>",
        (
            f'<span class="badge" style="background:{color};color:#07101c">'
            f"{escape(severity)}</span>"
        ),
        (
            f'<span class="badge" style="background:var(--panel2)">'
            f"{escape(_confidence(finding))}</span>"
        ),
        (
            f'<span class="badge" style="background:var(--panel2)">'
            f"{escape(_status(finding))}</span>"
        ),
        "<p><strong>Affected Asset:</strong> "
        f"<code>{escape(_asset(finding))}</code></p>",
        "<p><strong>Source:</strong> "
        f"{escape(_source(finding))}</p>",
    ]

    if cve:
        parts.append(
            "<p><strong>CVE:</strong> "
            f"<code>{escape(cve)}</code></p>"
        )

    for heading, key in (
        ("Description", "description"),
        ("Impact", "impact"),
        ("Remediation", "remediation"),
    ):
        value = _field(
            finding,
            key,
            "",
        )

        if value:
            parts.extend(
                [
                    f"<h3>{heading}</h3>",
                    f"<p>{escape(str(value))}</p>",
                ]
            )

    evidence = _field(
        finding,
        "evidence",
        "",
    )

    if evidence:
        parts.extend(
            [
                "<h3>Evidence</h3>",
                (
                    f"<pre>{escape(_json_block(evidence))}</pre>"
                ),
            ]
        )

    parts.append(
        "</article>"
    )

    return "".join(parts)


def _html_intelligence(
    records: Iterable[Any],
) -> str:
    """
    Render NVD/CPE/CVE/KEV intelligence records.

    Vulnerability-intelligence matches represent potential exposure from
    observed software identity. They do not by themselves confirm
    exploitability, successful exploitation, or compromise.
    """

    rows: list[str] = []

    for record in records:
        item = _intelligence_item(
            record
        )

        if not item:
            continue

        product = item["product"]
        version = item["version"]
        cpe = item["cpe"]
        cve = item["cve"]
        title = item["title"]
        severity = item["severity"]

        cvss_score = item["cvss_score"]
        cvss_version = item["cvss_version"]

        if cvss_score is None:
            cvss = "-"
        else:
            cvss = (
                f"{cvss_score} "
                f"({cvss_version})"
            )

        target = (
            item["target"]
            or item["host"]
            or "-"
        )

        port = item["port"]

        if port is not None:
            target = f"{target}:{port}"

        url = item["url"]

        if url:
            target = (
                f"{target} — {url}"
            )

        kev = (
            "Yes"
            if item["kev"]
            else "No"
        )

        kev_added = item[
            "kev_date_added"
        ]

        kev_due = item[
            "kev_due_date"
        ]

        ransomware = item[
            "kev_ransomware_use"
        ]

        if ransomware is True:
            ransomware_text = "Yes"
        elif ransomware is False:
            ransomware_text = "No"
        else:
            ransomware_text = "-"

        cwes = item["cwes"]

        if isinstance(
            cwes,
            (list, tuple, set),
        ):
            cwe_text = ", ".join(
                str(value).strip()
                for value in cwes
                if str(value).strip()
            ) or "-"
        else:
            cwe_text = (
                str(cwes).strip()
                or "-"
            )

        rows.append(
            "<tr>"
            f"<td><strong>{escape(product)}</strong>"
            f"<br><span class=\"small\">"
            f"{escape(version)}</span></td>"
            f"<td><code>{escape(cpe)}</code></td>"
            f"<td><code>{escape(cve)}</code>"
            f"<br>{escape(title)}</td>"
            f"<td>{escape(severity)}</td>"
            f"<td>{escape(cvss)}</td>"
            f"<td>{escape(target)}</td>"
            f"<td>{escape(kev)}</td>"
            f"<td>{escape(kev_added)}</td>"
            f"<td>{escape(kev_due)}</td>"
            f"<td>{escape(ransomware_text)}</td>"
            f"<td>{escape(cwe_text)}</td>"
            "</tr>"
        )

    if not rows:
        return ""

    return (
        "<h2>Vulnerability Intelligence</h2>"
        '<div class="card">'
        "<p>"
        "<strong>Potential exposure:</strong> "
        "NVD/CPE/CVE intelligence correlates observed "
        "software identity with vulnerability records. "
        "These matches require target-specific validation "
        "and do not by themselves confirm exploitability, "
        "successful exploitation, or compromise."
        "</p>"
        "</div>"
        '<div style="overflow-x:auto">'
        "<table>"
        "<thead>"
        "<tr>"
        "<th>Product / Version</th>"
        "<th>CPE</th>"
        "<th>CVE / Title</th>"
        "<th>Severity</th>"
        "<th>CVSS</th>"
        "<th>Asset</th>"
        "<th>KEV</th>"
        "<th>KEV Added</th>"
        "<th>KEV Due</th>"
        "<th>Ransomware</th>"
        "<th>CWE</th>"
        "</tr>"
        "</thead>"
        "<tbody>"
        + "".join(rows)
        + "</tbody>"
        "</table>"
        "</div>"
    )



def _html_document(
    title: str,
    subtitle: str,
    body: str,
) -> str:
    return (
        "<!doctype html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{escape(title)}</title>"
        f"<style>{_HTML_CSS}</style>"
        "</head>"
        "<body>"
        "<main>"
        "<header>"
        f"<h1>{escape(title)}</h1>"
        f'<div class="meta">{escape(subtitle)}</div>'
        "</header>"
        f"{body}"
        "</main>"
        "</body>"
        "</html>"
    )


def _professional_html(
    data: Mapping[str, Any],
) -> str:
    findings = sorted(
        list(
            data.get(
                "findings",
                [],
            )
        ),
        key=_finding_sort_key,
    )

    counts = _severity_counts(
        findings
    )

    cves = _cves(
        findings
    )

    intelligence = list(
        data.get(
            "vulnerability_intelligence_results",
            [],
        )
    )

    intelligence_summary = data.get(
        "vulnerability_intelligence",
        {},
    )

    metrics = "".join(
        (
            f'<div class="card"><div class="label">{severity}</div>'
            f'<div class="metric">{counts.get(severity, 0)}</div></div>'
        )
        for severity in _SEVERITIES
    )

    findings_html = (
        "".join(
            _html_finding(
                finding,
                index,
            )
            for index, finding in enumerate(
                findings,
                start=1,
            )
        )
        if findings
        else (
            '<div class="card"><strong>'
            "No security findings were identified."
            "</strong>"
            '<p class="small">'
            "This is not proof that the target is secure."
            "</p></div>"
        )
    )

    intelligence_html = _html_intelligence(
        intelligence
    )

    body = (
        '<section class="grid">'
        f'<div class="card"><div class="label">Total Findings</div>'
        f'<div class="metric">{len(findings)}</div></div>'
        f'<div class="card"><div class="label">CVEs</div>'
        f'<div class="metric">{len(cves)}</div></div>'
        f'<div class="card"><div class="label">NVD Matches</div>'
        f'<div class="metric">'
        f'{intelligence_summary.get("nvd", 0)}'
        f'</div></div>'
        f'<div class="card"><div class="label">CISA KEV</div>'
        f'<div class="metric">'
        f'{intelligence_summary.get("kev", 0)}'
        f'</div></div>'
        + metrics
        + "</section>"
        "<h2>Executive Summary</h2>"
        f"<p>Highest observed severity: "
        f"<strong>{escape(_highest_severity(findings))}</strong>.</p>"
        + intelligence_html
        + "<h2>Findings</h2>"
        + findings_html
    )

    return _html_document(
        "ScopeForgeX Security Assessment Report",
        (
            f"{data.get('target', '-')}"
            f" · {data.get('profile', '-')}"
            f" · run {data.get('run_id', '-')}"
        ),
        body,
    )


def _findings_html(
    data: Mapping[str, Any],
) -> str:
    findings = sorted(
        list(
            data.get(
                "findings",
                [],
            )
        ),
        key=_finding_sort_key,
    )

    counts = _severity_counts(
        findings
    )

    cves = _cves(
        findings
    )

    intelligence = list(
        data.get(
            "vulnerability_intelligence_results",
            [],
        )
    )

    intelligence_summary = data.get(
        "vulnerability_intelligence",
        {},
    )

    intelligence_html = _html_intelligence(
        intelligence
    )

    body = (
        '<section class="grid">'
        f'<div class="card"><div class="label">Findings</div>'
        f'<div class="metric">{len(findings)}</div></div>'
        f'<div class="card"><div class="label">Critical</div>'
        f'<div class="metric">{counts.get("Critical", 0)}</div></div>'
        f'<div class="card"><div class="label">High</div>'
        f'<div class="metric">{counts.get("High", 0)}</div></div>'
        f'<div class="card"><div class="label">Medium</div>'
        f'<div class="metric">{counts.get("Medium", 0)}</div></div>'
        f'<div class="card"><div class="label">CVEs</div>'
        f'<div class="metric">{len(cves)}</div></div>'
        f'<div class="card"><div class="label">NVD Matches</div>'
        f'<div class="metric">'
        f'{intelligence_summary.get("nvd", 0)}'
        f'</div></div>'
        f'<div class="card"><div class="label">CISA KEV</div>'
        f'<div class="metric">'
        f'{intelligence_summary.get("kev", 0)}'
        f'</div></div>'
        "</section>"
        + intelligence_html
        + "<h2>Security Findings</h2>"
    )

    if findings:
        body += "".join(
            _html_finding(
                finding,
                index,
            )
            for index, finding in enumerate(
                findings,
                start=1,
            )
        )
    else:
        body += (
            '<div class="card"><strong>'
            "No normalized security findings were recorded."
            '<p class="small">'
            "This does not exclude potential exposure identified "
            "through vulnerability intelligence."
            "</p></div>"
        )

    return _html_document(
        "ScopeForgeX Findings Report",
        (
            f"{data.get('target', '-')}"
            " · findings-oriented view"
        ),
        body,
    )


def _write_text(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content.rstrip() + "\n",
        encoding="utf-8",
    )


def _write_json(
    path: Path,
    data: Mapping[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            _serialize(data),
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )


def _report_data_from_state(
    data: Mapping[str, Any],
) -> ReportData:
    """
    Convert assembled Stage 6 state into the canonical ReportData model.

    Stage 6 remains responsible for collecting and deriving assessment state.
    ReportData is the structured representation consumed by the presentation
    and JSON export layers.
    """

    raw_statistics = data.get(
        "statistics",
        {},
    )

    if not isinstance(
        raw_statistics,
        Mapping,
    ):
        raw_statistics = {}

    statistics_fields = {
        "subdomains_found",
        "alive_hosts",
        "final_hosts",
        "urls_discovered",
        "files_generated",
        "tools_executed",
        "stages_executed",
        "stages_skipped",
        "findings_total",
        "findings_critical",
        "findings_high",
        "findings_medium",
        "findings_low",
        "findings_informational",
        "findings_confirmed",
        "findings_pending",
        "findings_false_positive",
    }

    statistics = ScanStatistics(
        **{
            key: raw_statistics[key]
            for key in statistics_fields
            if key in raw_statistics
        }
    )

    execution_results = _as_list(
        data.get(
            "execution_results",
            [],
        )
    )

    canonical_findings: list[Finding] = []

    for item in _as_list(
        data.get(
            "findings",
            [],
        )
    ):
        if isinstance(
            item,
            Finding,
        ):
            canonical_findings.append(
                item
            )
            continue

        if isinstance(
            item,
            Mapping,
        ):
            normalized = mapping_to_finding(
                item
            )

            canonical_findings.append(
                Finding(
                    finding_id=str(
                        getattr(
                            normalized,
                            "finding_id",
                            "",
                        )
                        or ""
                    ),
                    title=str(
                        getattr(
                            normalized,
                            "title",
                            "Assessment Observation",
                        )
                        or "Assessment Observation"
                    ),
                    category=str(
                        getattr(
                            normalized,
                            "category",
                            "security_issue",
                        )
                        or "security_issue"
                    ),
                    severity=str(
                        getattr(
                            normalized,
                            "severity",
                            "Informational",
                        )
                        or "Informational"
                    ),
                    confidence=str(
                        getattr(
                            normalized,
                            "confidence",
                            "Medium",
                        )
                        or "Medium"
                    ),
                    status=str(
                        getattr(
                            normalized,
                            "status",
                            "Pending",
                        )
                        or "Pending"
                    ),
                    target=str(
                        getattr(
                            normalized,
                            "target",
                            "",
                        )
                        or ""
                    ),
                    host=getattr(
                        normalized,
                        "host",
                        None,
                    ),
                    port=getattr(
                        normalized,
                        "port",
                        None,
                    ),
                    url=getattr(
                        normalized,
                        "url",
                        None,
                    ),
                    parameter=getattr(
                        normalized,
                        "parameter",
                        None,
                    ),
                    description=str(
                        getattr(
                            normalized,
                            "description",
                            "",
                        )
                        or ""
                    ),
                    impact=str(
                        getattr(
                            normalized,
                            "impact",
                            "",
                        )
                        or ""
                    ),
                    remediation=str(
                        getattr(
                            normalized,
                            "remediation",
                            "",
                        )
                        or ""
                    ),
                    evidence=_serialize(
                        getattr(
                            normalized,
                            "evidence",
                            None,
                        )
                    ),
                    source_tool=str(
                        getattr(
                            normalized,
                            "source_tool",
                            "",
                        )
                        or ""
                    ),
                    detection_method=str(
                        getattr(
                            normalized,
                            "detection_method",
                            "",
                        )
                        or ""
                    ),
                    timestamp=getattr(
                        normalized,
                        "timestamp",
                        None,
                    ),
                    metadata=dict(
                        getattr(
                            normalized,
                            "metadata",
                            {},
                        )
                        or {}
                    ),
                    cwe=getattr(
                        normalized,
                        "cwe",
                        None,
                    ),
                    cve=getattr(
                        normalized,
                        "cve",
                        None,
                    ),
                    references=list(
                        getattr(
                            normalized,
                            "references",
                            [],
                        )
                        or []
                    ),
                )
            )

    reporting_stages: list[ReportingStageResult] = []

    for item in _as_list(
        data.get(
            "stage_results",
            [],
        )
    ):
        if isinstance(
            item,
            ReportingStageResult,
        ):
            reporting_stages.append(
                item
            )
            continue

        if not isinstance(
            item,
            Mapping,
        ):
            continue

        phase = item.get(
            "phase",
            "",
        )

        if isinstance(
            phase,
            AssessmentPhase,
        ):
            reporting_phase = phase
        else:
            try:
                reporting_phase = AssessmentPhase(
                    str(
                        phase
                    )
                )
            except ValueError:
                reporting_phase = str(
                    phase
                )

        reporting_stages.append(
            ReportingStageResult(
                phase=reporting_phase,
                status=str(
                    item.get(
                        "status",
                        "",
                    )
                ),
            )
        )

    return ReportData(
        target=str(
            data.get(
                "target",
                "",
            )
            or ""
        ),
        profile=str(
            data.get(
                "profile",
                "",
            )
            or ""
        ),
        target_type=str(
            data.get(
                "target_type",
                "",
            )
            or ""
        ),
        start_time=data.get(
            "start_time"
        ),
        end_time=data.get(
            "end_time"
        ),
        statistics=statistics,
        generated_files=[
            str(item)
            for item in _as_list(
                data.get(
                    "generated_files",
                    [],
                )
            )
            if str(item)
        ],
        stages=reporting_stages,
        findings=canonical_findings,
        tool_results=_tool_results_projection(
            execution_results
        ),
        warnings=[
            str(item)
            for item in _as_list(
                data.get(
                    "warnings",
                    [],
                )
            )
        ],
        errors=[
            str(item)
            for item in _as_list(
                data.get(
                    "errors",
                    [],
                )
            )
        ],
        duration_seconds=float(
            data.get(
                "duration",
                0.0,
            )
            or 0.0
        ),
        run_id=str(
            data.get(
                "run_id",
                "",
            )
            or ""
        ),
        schema_version=str(
            data.get(
                "schema_version",
                "4.0",
            )
            or "4.0"
        ),
        correlation_groups=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "correlation_groups",
                    [],
                )
            )
        ],
        correlated_findings=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "correlated_findings",
                    [],
                )
            )
        ],
        collector_results=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "collector_results",
                    [],
                )
            )
        ],
        execution_results=[
            _serialize(item)
            for item in execution_results
        ],
        native_analyzer_results=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "native_analyzer_results",
                    [],
                )
            )
        ],
        vulnerability_intelligence_results=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "vulnerability_intelligence_results",
                    [],
                )
            )
        ],
        software_assessments=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "software_assessments",
                    [],
                )
            )
        ],
        evidence_references=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "evidence_references",
                    [],
                )
            )
        ],
        raw_evidence_references=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "raw_evidence_references",
                    [],
                )
            )
        ],
        finding_evidence_references=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "finding_evidence_references",
                    [],
                )
            )
        ],
        correlated_evidence_references=[
            _serialize(item)
            for item in _as_list(
                data.get(
                    "correlated_evidence_references",
                    [],
                )
            )
        ],
        summary=_mapping(
            data.get(
                "summary",
                {},
            )
        ),
        vulnerability_intelligence=_mapping(
            data.get(
                "vulnerability_intelligence",
                {},
            )
        ),
        analysis_metadata=_mapping(
            data.get(
                "analysis_metadata",
                {},
            )
        ),
        report_views=_mapping(
            data.get(
                "report_views",
                {},
            )
        ),
    )


def stage6_report_cleanup(
    ctx: dict[str, Any],
) -> None:
    """Generate professional, findings-oriented and canonical outputs."""

    stage(
        "STAGE 6 — REPORTING & CLEANUP",
        "green",
    )

    outdir = Path(
        str(
            ctx.get(
                "outdir",
                ".",
            )
        )
    )

    paths = _generated_paths(
        outdir
    )

    try:
        for path in paths.values():
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        # AnalysisPipeline exposes processing metadata through AnalysisResult.
        # Copy it into the reporting context when available without requiring
        # Stage 6 to depend on the pipeline implementation.
        analysis_result = ctx.get("analysis_result")
        if analysis_result is not None:
            analysis_metadata = getattr(
                analysis_result,
                "metadata",
                None,
            )
            if isinstance(analysis_metadata, Mapping):
                ctx["analysis_metadata"] = dict(
                    analysis_metadata
                )

        data = _report_state(
            ctx,
            paths,
        )

        # Publish a compact report projection. Raw HTTP request/response
        # payloads remain available in runtime/raw-evidence storage but are
        # intentionally excluded from the canonical human-facing report.
        data = _sanitize_report_payload(
            data
        )

        report = _report_data_from_state(
            data
        )

        generator = ReportGenerator(
            report
        )

        generator.generate_professional_markdown(
            str(
                paths["professional_markdown"]
            )
        )

        generator.generate_findings_markdown(
            str(
                paths["findings_markdown"]
            )
        )

        generator.generate_professional_html(
            str(
                paths["professional_html"]
            )
        )

        generator.generate_findings_html(
            str(
                paths["findings_html"]
            )
        )

        JSONReportExporter(
            report
        ).export(
            str(
                paths["canonical_json"]
            )
        )

        # Compatibility files preserve the existing root-level entry points.
        professional_md = paths[
            "professional_markdown"
        ].read_text(
            encoding="utf-8"
        )

        findings_md = paths[
            "findings_markdown"
        ].read_text(
            encoding="utf-8"
        )

        _write_text(
            paths["markdown"],
            professional_md,
        )

        _write_text(
            paths["findings"],
            findings_md,
        )

        JSONReportExporter(
            report
        ).export(
            str(
                paths["json"]
            )
        )

        # Record exact report paths after successful creation.
        ctx[
            "report_paths"
        ] = {
            key: str(path)
            for key, path in paths.items()
        }

        ctx[
            "report_data"
        ] = report

        generated_files = ctx.setdefault(
            "generated_files",
            [],
        )

        for path in paths.values():
            value = str(path)
            if value not in generated_files:
                generated_files.append(
                    value
                )

        info(
            f"Professional report: "
            f"{paths['professional_markdown']}"
        )

        info(
            f"Professional HTML: "
            f"{paths['professional_html']}"
        )

        info(
            f"Findings report: "
            f"{paths['findings_markdown']}"
        )

        info(
            f"Findings HTML: "
            f"{paths['findings_html']}"
        )

        info(
            f"Canonical JSON: "
            f"{paths['canonical_json']}"
        )

        ok(
            "Professional + Findings reports generated successfully."
        )

    except Exception as exc:
        err(
            f"Report generation failed: {type(exc).__name__}: {exc}"
        )

        ctx.setdefault(
            "errors",
            [],
        ).append(
            f"Stage 6 reporting failed: "
            f"{type(exc).__name__}: {exc}"
        )

        return

    warn(
        "Cleanup skipped: assessment artifacts are preserved."
    )

    ok(
        "Stage 6 reporting and cleanup finished."
    )


__all__ = [
    "stage6_report_cleanup",
]
