"""
ScopeForgeX Report Generator
============================

Presentation helpers for the canonical ScopeForgeX ReportData model.

The generator exposes two report views:

- Professional
- Findings-oriented

Both views consume the same ReportData object and represent one canonical
assessment state.

ScopeForgeX 4.0.0
"""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any

from .models import ReportData


_SEVERITIES = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


def _finding_data(
    finding: Any,
) -> dict[str, Any]:
    if isinstance(
        finding,
        dict,
    ):
        return dict(
            finding
        )

    if hasattr(
        finding,
        "as_dict",
    ):
        try:
            value = finding.as_dict()

            if isinstance(
                value,
                dict,
            ):
                return dict(
                    value
                )
        except Exception:
            pass

    return {}


def _severity(
    finding: Any,
) -> str:
    value = str(
        _finding_data(finding).get(
            "severity",
            "Informational",
        )
    ).strip().lower()

    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }.get(
        value,
        value.title(),
    )


def _title(
    finding: Any,
) -> str:
    return str(
        _finding_data(finding).get(
            "title",
            "Untitled Finding",
        )
    )


def _asset(
    finding: Any,
) -> str:
    data = _finding_data(
        finding
    )

    for key in (
        "url",
        "host",
        "target",
    ):
        value = data.get(
            key
        )

        if value:
            return str(
                value
            )

    return "Unspecified"


def _cve(
    finding: Any,
) -> str:
    data = _finding_data(
        finding
    )

    value = data.get(
        "cve"
    )

    if value:
        return str(
            value
        ).strip()

    metadata = data.get(
        "metadata"
    )

    if isinstance(
        metadata,
        dict,
    ):
        for item in (
            metadata.get(
                "cves",
                [],
            )
            or []
        ):
            if str(
                item
            ).strip():
                return str(
                    item
                ).strip()

    return ""


def _metadata(
    finding: Any,
) -> dict[str, Any]:
    value = _finding_data(
        finding
    ).get(
        "metadata",
        {},
    )

    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def _cvss_score(
    finding: Any,
) -> Any:
    data = _finding_data(
        finding
    )
    metadata = _metadata(
        finding
    )

    for key in (
        "cvss_score",
        "cvss",
        "cvssScore",
    ):
        value = data.get(
            key
        )

        if value is not None:
            return value

        value = metadata.get(
            key
        )

        if value is not None:
            return value

    return None


def _cvss_version(
    finding: Any,
) -> str:
    data = _finding_data(
        finding
    )
    metadata = _metadata(
        finding
    )

    for key in (
        "cvss_version",
        "cvssVersion",
    ):
        value = data.get(
            key
        )

        if value:
            return str(
                value
            )

        value = metadata.get(
            key
        )

        if value:
            return str(
                value
            )

    return ""


def _cwes(
    finding: Any,
) -> list[str]:
    data = _finding_data(
        finding
    )
    metadata = _metadata(
        finding
    )

    value = data.get(
        "cwes"
    )

    if value is None:
        value = metadata.get(
            "cwes"
        )

    if value is None:
        value = data.get(
            "cwe"
        )

    if value is None:
        value = metadata.get(
            "cwe"
        )

    if isinstance(
        value,
        str,
    ):
        return [
            value
        ] if value.strip() else []

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return []


def _kev_status(
    finding: Any,
) -> bool:
    metadata = _metadata(
        finding
    )

    return (
        metadata.get(
            "kev"
        )
        is True
    )


def _intelligence_summary(
    report: ReportData,
) -> dict[str, int]:
    """
    Summarize NVD/CVE/KEV intelligence attached to the report.
    """

    records = list(
        getattr(
            report,
            "vulnerability_intelligence_results",
            [],
        )
        or []
    )

    cves: set[str] = set()
    kev = 0
    nvd = 0
    version_matches = 0

    for record in records:
        data = _finding_data(
            record
        )

        cve = data.get(
            "cve"
        )

        if cve:
            cves.add(
                str(cve).strip()
            )

        metadata = data.get(
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            dict,
        ):
            metadata = {}

        kev += int(
            metadata.get(
                "kev"
            )
            is True
        )

        nvd += int(
            metadata.get(
                "intelligence_source"
            )
            == "NVD"
            or data.get(
                "source_tool"
            )
            == "NVD"
        )

        version_matches += int(
            metadata.get(
                "version_based_match"
            )
            is True
        )

    return {
        "observations": len(
            records
        ),
        "cves": len(
            cves
        ),
        "kev": kev,
        "nvd": nvd,
        "version_matches": version_matches,
    }


def _serialize_evidence(
    evidence: Any,
) -> str:
    if hasattr(
        evidence,
        "as_dict",
    ):
        try:
            evidence = evidence.as_dict()
        except Exception:
            pass

    try:
        return json.dumps(
            evidence,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return str(
            evidence
        )


class ReportGenerator:
    """
    Generate the human-facing report views from ReportData.
    """

    def __init__(
        self,
        report: ReportData,
    ) -> None:
        self.report = report

    def _software_assessment_data(self, assessment):
        if hasattr(assessment, "as_dict"):
            data = assessment.as_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            data = {
                key: getattr(assessment, key, None)
                for key in (
                    "product",
                    "version",
                    "vendor",
                    "cpe",
                    "target",
                    "host",
                    "port",
                    "url",
                    "source_tool",
                    "detection_method",
                    "confidence",
                    "nvd_checked",
                    "applicable_cve_count",
                    "kev_count",
                )
            }

        return data

    def _sorted_findings(
        self,
    ) -> list[Any]:
        findings = list(
            getattr(
                self.report,
                "findings",
                [],
            )
        )

        rank = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Informational": 4,
        }

        findings.sort(
            key=lambda finding: (
                rank.get(
                    _severity(finding),
                    5,
                ),
                _title(
                    finding
                ).lower(),
            )
        )

        return findings

    def _severity_counts(
        self,
    ) -> dict[str, int]:
        counts = {
            severity: 0
            for severity in _SEVERITIES
        }

        for finding in self._sorted_findings():
            severity = _severity(
                finding
            )

            counts.setdefault(
                severity,
                0,
            )

            counts[severity] += 1

        return counts

    def _finding_block(
        self,
        finding: Any,
        index: int,
    ) -> str:
        data = _finding_data(
            finding
        )

        finding_id = str(
            data.get(
                "finding_id",
                data.get(
                    "id",
                    f"SF-{index:03d}",
                ),
            )
        )

        confidence = str(
            data.get(
                "confidence",
                "Medium",
            )
        )

        status = str(
            data.get(
                "status",
                "Pending",
            )
        )

        source_tool = str(
            data.get(
                "source_tool",
                "ScopeForgeX",
            )
        )

        category = str(
            data.get(
                "category",
                "security_issue",
            )
        )

        cve = _cve(
            finding
        )

        cvss_score = _cvss_score(
            finding
        )

        cvss_version = _cvss_version(
            finding
        )

        cwes = _cwes(
            finding
        )

        lines = [
            f"### {finding_id} — {_title(finding)}",
            "",
            "| Severity | Confidence | Validation | Source |",
            "|---|---|---|---|",
            (
                f"| **{_severity(finding)}** | "
                f"{confidence} | "
                f"{status} | "
                f"{source_tool} |"
            ),
            "",
            f"**Affected Asset:** `{_asset(finding)}`",
            "",
            f"**Category:** `{category}`",
            "",
        ]

        parameter = data.get(
            "parameter"
        )

        if parameter:
            lines.extend(
                [
                    f"**Parameter:** `{parameter}`",
                    "",
                ]
            )

        if cve:
            lines.extend(
                [
                    f"**CVE:** `{cve}`",
                    "",
                ]
            )

        if cvss_score is not None:
            cvss_label = (
                f"CVSS {cvss_version}"
                if cvss_version
                else "CVSS"
            )

            lines.extend(
                [
                    f"**{cvss_label}:** `{cvss_score}`",
                    "",
                ]
            )

        if cwes:
            lines.extend(
                [
                    f"**CWE:** "
                    f"{', '.join(f'`{item}`' for item in cwes)}",
                    "",
                ]
            )

        if _kev_status(
            finding
        ):
            lines.extend(
                [
                    "**CISA KEV:** `Yes`",
                    "",
                ]
            )

        for heading, key in (
            ("Description", "description"),
            ("Impact", "impact"),
            ("Remediation", "remediation"),
        ):
            value = data.get(
                key
            )

            if value:
                lines.extend(
                    [
                        f"**{heading}**",
                        "",
                        str(value),
                        "",
                    ]
                )

        evidence = data.get(
            "evidence"
        )

        if evidence:
            lines.extend(
                [
                    "**Evidence**",
                    "",
                    "```json",
                    _serialize_evidence(
                        evidence
                    ),
                    "```",
                    "",
                ]
            )

        detection = data.get(
            "detection_method"
        )

        if detection:
            lines.extend(
                [
                    f"**Detection:** {detection}",
                    "",
                ]
            )

        references = data.get(
            "references",
            [],
        ) or []

        if references:
            lines.extend(
                [
                    "**References**",
                    "",
                ]
            )

            lines.extend(
                f"- {reference}"
                for reference in references
            )

            lines.append("")

        return "\n".join(
            lines
        )

    def generate_markdown(
        self,
        output_file: str,
    ) -> None:
        """
        Compatibility alias for the Professional Markdown report.
        """

        self.generate_professional_markdown(
            output_file
        )

    def generate_professional_markdown(
        self,
        output_file: str,
    ) -> None:
        findings = self._sorted_findings()
        counts = self._severity_counts()
        intelligence = _intelligence_summary(
            self.report
        )

        risk = next(
            (
                severity
                for severity in _SEVERITIES
                if counts.get(
                    severity,
                    0,
                )
            ),
            "No Material Finding",
        )

        statistics = self.report.statistics

        lines = [
            "# ScopeForgeX Security Assessment Report",
            "",
            "> Professional assessment view.",
            "",
            "## 1. Executive Summary",
            "",
            (
                f"The assessment identified **{len(findings)}** finding(s). "
                f"The highest observed severity is **{risk}**."
                if findings
                else
                "No vulnerabilities or other security findings were "
                "recorded by the automated assessment."
            ),
            "",
            f"- **Target:** `{self.report.target}`",
            f"- **Target Type:** `{self.report.target_type}`",
            f"- **Profile:** `{self.report.profile}`",
            f"- **Run ID:** `{self.report.run_id}`",
            f"- **Duration:** "
            f"`{self.report.duration_seconds:.2f} seconds`",
            "",
            "### Risk Summary",
            "",
            "| Severity | Findings |",
            "|---|---:|",
        ]

        for severity in _SEVERITIES:
            lines.append(
                f"| {severity} | {counts.get(severity, 0)} |"
            )

        lines.extend(
            [
                "",
                "### Vulnerability Intelligence",
                "",
                "| Metric | Count |",
                "|---|---:|",
                (
                    f"| Intelligence observations | "
                    f"{intelligence['observations']} |"
                ),
                f"| CVEs | {intelligence['cves']} |",
                f"| NVD matches | {intelligence['nvd']} |",
                f"| KEV matches | {intelligence['kev']} |",
                (
                    f"| Version-based matches | "
                    f"{intelligence['version_matches']} |"
                ),
                "",
                "## 2. Assessment Scope",
                "",
                f"- **Target:** `{self.report.target}`",
                f"- **Target Type:** `{self.report.target_type}`",
                f"- **Started:** `{self.report.start_time}`",
                f"- **Finished:** `{self.report.end_time}`",
                f"- **Run ID:** `{self.report.run_id}`",
                "",
                "## 3. Rules of Engagement / Limitations",
                "",
                "- Scope and authorization are defined by workflow input.",
                "- Automated detections require analyst validation before "
                "being treated as confirmed vulnerabilities.",
                "- No-findings results do not establish that the target is secure.",
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
                f"{statistics.subdomains_found}",
                f"- **Alive hosts:** "
                f"{statistics.alive_hosts}",
                f"- **Final hosts:** "
                f"{statistics.final_hosts}",
                f"- **URLs discovered:** "
                f"{statistics.urls_discovered}",
                "",
                "## 6. Risk Summary",
                "",
                f"**Highest observed severity:** **{risk}**",
                "",
                "Severity and confidence are intentionally separate.",
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
                lines.extend(
                    [
                        self._finding_block(
                            finding,
                            index,
                        ),
                        "",
                    ]
                )
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
                "Evidence remains attached to the canonical findings and "
                "preserved in the assessment artifact set.",
                "",
                f"- **Evidence references:** "
                f"{len(self.report.evidence_references)}",
                f"- **Finding evidence references:** "
                f"{len(self.report.finding_evidence_references)}",
                f"- **Correlated evidence references:** "
                f"{len(self.report.correlated_evidence_references)}",
                "",
                "## 9. Impact",
                "",
                "Finding-specific impact statements are documented above.",
                "",
                "## 10. Remediation",
                "",
                "Finding-specific remediation guidance is documented above.",
                "",
                "## 11. Validation Status",
                "",
                "| Status | Findings |",
                "|---|---:|",
            ]
        )

        status_counts = Counter(
            str(
                _finding_data(
                    finding
                ).get(
                    "status",
                    "Pending",
                )
            )
            for finding in findings
        )

        if status_counts:
            for status, count in sorted(
                status_counts.items()
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
                "| Tool | Status | Findings |",
                "|---|---|---:|",
            ]
        )

        source_counts = Counter(
            str(
                _finding_data(
                    finding
                ).get(
                    "source_tool",
                    "ScopeForgeX",
                )
            )
            for finding in findings
        )

        for tool, status in sorted(
            self.report.tool_results.items()
        ):
            lines.append(
                f"| {tool} | `{status}` | "
                f"{source_counts.get(tool, 0)} |"
            )

        if not self.report.tool_results:
            lines.append(
                "| None recorded | — | 0 |"
            )

        lines.extend(
            [
                "",
                "## 13. Assessment Execution",
                "",
                "| Metric | Value |",
                "|---|---:|",
                f"| Tools executed | {statistics.tools_executed} |",
                f"| Stages executed | {statistics.stages_executed} |",
                f"| Stages skipped | {statistics.stages_skipped} |",
                f"| Total findings | {statistics.findings_total} |",
                f"| Confirmed findings | {statistics.findings_confirmed} |",
                f"| Pending findings | {statistics.findings_pending} |",
                (
                    f"| False-positive findings | "
                    f"{statistics.findings_false_positive} |"
                ),
                f"| Files generated | {statistics.files_generated} |",
                "",
                "## 14. Assessment Stages",
                "",
                "| Stage | Status |",
                "|---|---|",
            ]
        )

        if self.report.stages:
            for stage_result in self.report.stages:
                if hasattr(
                    stage_result,
                    "as_dict",
                ):
                    data = stage_result.as_dict()
                else:
                    data = {}

                lines.append(
                    f"| {data.get('phase', 'Unknown')} | "
                    f"`{data.get('status', 'Unknown')}` |"
                )
        else:
            lines.append(
                "| None recorded | — |"
            )

        lines.extend(
            [
                "",
                "## 15. Native ScopeForgeX Analysis",
                "",
                "| Analyzer | Results | Findings |",
                "|---|---:|---:|",
            ]
        )

        native_counts: dict[str, list[int]] = {}

        for result in (
            self.report.native_analyzer_results
        ):
            if hasattr(
                result,
                "as_dict",
            ):
                data = result.as_dict()
            elif isinstance(
                result,
                dict,
            ):
                data = result
            else:
                data = {}

            analyzer = str(
                data.get(
                    "analyzer",
                    "unknown",
                )
            )

            native_counts.setdefault(
                analyzer,
                [0, 0],
            )

            native_counts[analyzer][0] += 1

            native_counts[analyzer][1] += len(
                data.get(
                    "findings",
                    [],
                )
                or []
            )

        for analyzer, values in sorted(
            native_counts.items()
        ):
            lines.append(
                f"| {analyzer} | {values[0]} | {values[1]} |"
            )

        if not native_counts:
            lines.append(
                "| None recorded | 0 | 0 |"
            )

        software_assessment_lines = [
            (
                "| "
                + " | ".join(
                    str(
                        self._software_assessment_data(
                            assessment
                        ).get(key)
                        or "—"
                    ).replace("|", "\\|")
                    for key in (
                        "product",
                        "version",
                        "vendor",
                        "cpe",
                        "confidence",
                    )
                )
                + " | "
                + (
                    "Yes"
                    if self._software_assessment_data(
                        assessment
                    ).get("nvd_checked")
                    else "No"
                )
                + " | "
                + str(
                    self._software_assessment_data(
                        assessment
                    ).get(
                        "applicable_cve_count",
                        0,
                    )
                )
                + " | "
                + str(
                    self._software_assessment_data(
                        assessment
                    ).get(
                        "kev_count",
                        0,
                    )
                )
                + " |"
            )
            for assessment in getattr(
                self.report,
                "software_assessments",
                [],
            )
        ]

        lines.extend(
            [
                "",
                "## 16. Vulnerability Intelligence",
                "",
                "| Metric | Value |",
                "|---|---:|",
                (
                    f"| Intelligence observations | "
                    f"{intelligence['observations']} |"
                ),
                f"| Unique CVEs | {intelligence['cves']} |",
                f"| NVD matches | {intelligence['nvd']} |",
                f"| KEV matches | {intelligence['kev']} |",
                (
                    f"| Version-based matches | "
                    f"{intelligence['version_matches']} |"
                ),
                "",
                "Intelligence matches represent potential exposure and "
                "require target-specific validation before being treated "
                "as confirmed vulnerabilities.",
                "",
                "### Software Assessments",
                "",
                "Software assessments represent identified software "
                "components evaluated against NVD/CVE intelligence. "
                "A zero-CVE assessment is informational and is not a "
                "confirmed vulnerability.",
                "",
                "| Product | Version | Vendor | CPE | Confidence | NVD Checked | Applicable CVEs | KEV |",
                "|---|---|---|---|---|---|---:|---:|",
                *(
                    software_assessment_lines
                    if software_assessment_lines
                    else [
                        "No software assessments recorded."
                    ]
                ),
                "",
                "## 17. Appendix",
                "",
                f"- **Warnings:** {len(self.report.warnings)}",
                f"- **Errors:** {len(self.report.errors)}",
                f"- **Generated files:** "
                f"{len(self.report.generated_files)}",
                f"- **Schema version:** `{self.report.schema_version}`",
                f"- **Report generator:** "
                f"`{self.report.metadata.generator}`",
                f"- **Report version:** "
                f"`{self.report.metadata.version}`",
                "",
            ]
        )

        if self.report.warnings:
            lines.extend(
                [
                    "### Warnings",
                    "",
                ]
            )

            lines.extend(
                f"- {warning}"
                for warning in self.report.warnings
            )

            lines.append("")

        if self.report.errors:
            lines.extend(
                [
                    "### Errors",
                    "",
                ]
            )

            lines.extend(
                f"- {error}"
                for error in self.report.errors
            )

            lines.append("")

        path = Path(
            output_file
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            "\n".join(
                lines
            ).rstrip()
            + "\n",
            encoding="utf-8",
        )

    def generate_findings_markdown(
        self,
        output_file: str,
    ) -> None:
        findings = self._sorted_findings()
        counts = self._severity_counts()

        cves = sorted(
            {
                _cve(
                    finding
                )
                for finding in findings
                if _cve(
                    finding
                )
            }
        )

        intelligence = _intelligence_summary(
            self.report
        )

        assets = sorted(
            {
                _asset(
                    finding
                )
                for finding in findings
            }
        )

        lines = [
            "# ScopeForgeX Findings Report",
            "",
            "> Findings-oriented view focused on vulnerabilities, "
            "misconfigurations, exposures and CVE-associated findings.",
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
            (
                f"| Informational | "
                f"**{counts.get('Informational', 0)}** |"
            ),
            f"| CVEs | **{len(cves)}** |",
            f"| Affected assets | **{len(assets)}** |",
            f"| NVD matches | **{intelligence['nvd']}** |",
            f"| KEV matches | **{intelligence['kev']}** |",
            (
                f"| Version-based matches | "
                f"**{intelligence['version_matches']}** |"
            ),
            "",
            "## Findings",
            "",
        ]

        if findings:
            for index, finding in enumerate(
                findings,
                start=1,
            ):
                lines.extend(
                    [
                        self._finding_block(
                            finding,
                            index,
                        ),
                        "",
                    ]
                )
        else:
            lines.extend(
                [
                    "No vulnerabilities or security findings were recorded.",
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
                    "| CVE | Severity | Finding | Asset |",
                    "|---|---|---|---|",
                ]
            )

            for finding in findings:
                cve = _cve(
                    finding
                )

                if not cve:
                    continue

                data = _finding_data(
                    finding
                )

                lines.append(
                    f"| `{cve}` | "
                    f"{_severity(finding)} | "
                    f"`{data.get('finding_id', data.get('id', ''))}` | "
                    f"`{_asset(finding)}` |"
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
                _asset(
                    finding
                )
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
                "## Assessment Context",
                "",
                f"- **Target:** `{self.report.target}`",
                f"- **Target Type:** `{self.report.target_type}`",
                f"- **Profile:** `{self.report.profile}`",
                f"- **Run ID:** `{self.report.run_id}`",
                f"- **Duration:** "
                f"`{self.report.duration_seconds:.2f} seconds`",
                "",
                "## Validation Status",
                "",
                "| Status | Findings |",
                "|---|---:|",
            ]
        )

        status_counts = Counter(
            str(
                _finding_data(
                    finding
                ).get(
                    "status",
                    "Pending",
                )
            )
            for finding in findings
        )

        if status_counts:
            for status, count in sorted(
                status_counts.items()
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
                "## Evidence Summary",
                "",
                f"- **Evidence references:** "
                f"{len(self.report.evidence_references)}",
                f"- **Finding evidence references:** "
                f"{len(self.report.finding_evidence_references)}",
                f"- **Correlated evidence references:** "
                f"{len(self.report.correlated_evidence_references)}",
                "",
                "## Vulnerability Intelligence",
                "",
                (
                    "NVD/CVE matches and CISA KEV associations are "
                    "intelligence signals. They represent potential "
                    "exposure and do not independently confirm "
                    "target-specific exploitability."
                ),
                "",
            ]
        )

        path = Path(
            output_file
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            "\n".join(
                lines
            ).rstrip()
            + "\n",
            encoding="utf-8",
        )

    def _html_finding(
        self,
        finding: Any,
        index: int,
    ) -> str:
        data = _finding_data(
            finding
        )

        finding_id = str(
            data.get(
                "finding_id",
                data.get(
                    "id",
                    f"SF-{index:03d}",
                ),
            )
        )

        confidence = str(
            data.get(
                "confidence",
                "Medium",
            )
        )

        status = str(
            data.get(
                "status",
                "Pending",
            )
        )

        source = str(
            data.get(
                "source_tool",
                "ScopeForgeX",
            )
        )

        category = str(
            data.get(
                "category",
                "security_issue",
            )
        )

        cve = _cve(
            finding
        )

        cvss_score = _cvss_score(
            finding
        )

        cvss_version = _cvss_version(
            finding
        )

        cwes = _cwes(
            finding
        )

        pieces = [
            '<article class="finding">',
            (
                f"<div class=\"finding-header\">"
                f"<div>"
                f"<div class=\"finding-id\">"
                f"{escape(finding_id)}"
                f"</div>"
                f"<h2>{escape(_title(finding))}</h2>"
                f"</div>"
                f"<span class=\"badge\">"
                f"{escape(_severity(finding))}"
                f"</span>"
                f"</div>"
            ),
            (
                "<div class=\"finding-meta\">"
                f"<span><strong>Confidence:</strong> "
                f"{escape(confidence)}</span>"
                f"<span><strong>Status:</strong> "
                f"{escape(status)}</span>"
                f"<span><strong>Source:</strong> "
                f"{escape(source)}</span>"
                f"<span><strong>Category:</strong> "
                f"{escape(category)}</span>"
                "</div>"
            ),
            (
                f"<p><strong>Affected Asset:</strong> "
                f"<code>{escape(_asset(finding))}</code></p>"
            ),
        ]

        parameter = data.get(
            "parameter"
        )

        if parameter:
            pieces.append(
                f"<p><strong>Parameter:</strong> "
                f"<code>{escape(str(parameter))}</code></p>"
            )

        if cve:
            pieces.append(
                f"<p><strong>CVE:</strong> "
                f"<code>{escape(cve)}</code></p>"
            )

        if cvss_score is not None:
            cvss_label = (
                f"CVSS {cvss_version}"
                if cvss_version
                else "CVSS"
            )

            pieces.append(
                f"<p><strong>{escape(cvss_label)}:</strong> "
                f"<code>{escape(str(cvss_score))}</code></p>"
            )

        if cwes:
            pieces.append(
                f"<p><strong>CWE:</strong> "
                f"{escape(', '.join(cwes))}</p>"
            )

        if _kev_status(
            finding
        ):
            pieces.append(
                '<p><strong>CISA KEV:</strong> '
                '<span class="kev">Yes</span></p>'
            )

        for heading, key in (
            ("Description", "description"),
            ("Impact", "impact"),
            ("Remediation", "remediation"),
        ):
            value = data.get(
                key
            )

            if value:
                pieces.extend(
                    [
                        f"<h3>{escape(heading)}</h3>",
                        f"<p>{escape(str(value))}</p>",
                    ]
                )

        detection = data.get(
            "detection_method"
        )

        if detection:
            pieces.extend(
                [
                    "<h3>Detection</h3>",
                    f"<p>{escape(str(detection))}</p>",
                ]
            )

        evidence = data.get(
            "evidence"
        )

        if evidence:
            pieces.extend(
                [
                    "<h3>Evidence</h3>",
                    "<pre>",
                    escape(
                        _serialize_evidence(
                            evidence
                        )
                    ),
                    "</pre>",
                ]
            )

        references = data.get(
            "references",
            [],
        ) or []

        if references:
            pieces.extend(
                [
                    "<h3>References</h3>",
                    "<ul>",
                ]
            )

            pieces.extend(
                f"<li>{escape(str(reference))}</li>"
                for reference in references
            )

            pieces.append(
                "</ul>"
            )

        pieces.append(
            "</article>"
        )

        return "".join(
            pieces
        )

    def _html(
        self,
        title: str,
        subtitle: str,
    ) -> str:
        findings = self._sorted_findings()
        counts = self._severity_counts()
        intelligence = _intelligence_summary(
            self.report
        )

        card_items = [
            ("Findings", len(findings)),
            (
                "Critical",
                counts.get(
                    "Critical",
                    0,
                ),
            ),
            (
                "High",
                counts.get(
                    "High",
                    0,
                ),
            ),
            (
                "Medium",
                counts.get(
                    "Medium",
                    0,
                ),
            ),
            (
                "Low",
                counts.get(
                    "Low",
                    0,
                ),
            ),
            (
                "CVEs",
                intelligence["cves"],
            ),
            (
                "KEV",
                intelligence["kev"],
            ),
        ]

        cards = "".join(
            (
                '<div class="card">'
                f'<div class="label">{escape(label)}</div>'
                f'<div class="metric">{value}</div>'
                "</div>"
            )
            for label, value in card_items
        )

        if findings:
            finding_html = "".join(
                self._html_finding(
                    finding,
                    index,
                )
                for index, finding in enumerate(
                    findings,
                    start=1,
                )
            )
        else:
            finding_html = (
                '<div class="card"><strong>'
                "No findings recorded."
                "</strong></div>"
            )

        tool_rows = []

        for tool, status in sorted(
            self.report.tool_results.items()
        ):
            source_count = sum(
                1
                for finding in findings
                if _finding_data(
                    finding
                ).get(
                    "source_tool",
                    "ScopeForgeX",
                )
                == tool
            )

            tool_rows.append(
                "<tr>"
                f"<td>{escape(str(tool))}</td>"
                f"<td>{escape(str(status))}</td>"
                f"<td>{source_count}</td>"
                "</tr>"
            )

        if not tool_rows:
            tool_rows.append(
                "<tr>"
                "<td>None recorded</td>"
                "<td>—</td>"
                "<td>0</td>"
                "</tr>"
            )

        stage_rows = []

        for stage_result in self.report.stages:
            if hasattr(
                stage_result,
                "as_dict",
            ):
                data = stage_result.as_dict()
            else:
                data = {}

            stage_rows.append(
                "<tr>"
                f"<td>{escape(str(data.get('phase', 'Unknown')))}</td>"
                f"<td>{escape(str(data.get('status', 'Unknown')))}</td>"
                "</tr>"
            )

        if not stage_rows:
            stage_rows.append(
                "<tr>"
                "<td>None recorded</td>"
                "<td>—</td>"
                "</tr>"
            )

        native_rows = []

        native_counts: dict[str, list[int]] = {}

        for result in (
            self.report.native_analyzer_results
        ):
            if hasattr(
                result,
                "as_dict",
            ):
                data = result.as_dict()
            elif isinstance(
                result,
                dict,
            ):
                data = result
            else:
                data = {}

            analyzer = str(
                data.get(
                    "analyzer",
                    "unknown",
                )
            )

            native_counts.setdefault(
                analyzer,
                [0, 0],
            )

            native_counts[analyzer][0] += 1

            native_counts[analyzer][1] += len(
                data.get(
                    "findings",
                    [],
                )
                or []
            )

        for analyzer, values in sorted(
            native_counts.items()
        ):
            native_rows.append(
                "<tr>"
                f"<td>{escape(analyzer)}</td>"
                f"<td>{values[0]}</td>"
                f"<td>{values[1]}</td>"
                "</tr>"
            )

        if not native_rows:
            native_rows.append(
                "<tr>"
                "<td>None recorded</td>"
                "<td>0</td>"
                "<td>0</td>"
                "</tr>"
            )

        statistics = self.report.statistics

        css = """
:root {
    color-scheme: dark;
    --bg: #08111f;
    --panel: #101b2d;
    --panel2: #17263d;
    --text: #edf4ff;
    --muted: #9eacc2;
    --border: #2b3d59;
    --accent: #63b3ff;
    --danger: #ff6b6b;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background:
        linear-gradient(
            135deg,
            #07101c,
            #0b1424
        );
    color: var(--text);
    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
    line-height: 1.55;
}

main {
    max-width: 1180px;
    margin: auto;
    padding: 46px 24px 80px;
}

header {
    margin-bottom: 24px;
}

h1 {
    font-size: 2.35rem;
    letter-spacing: -.035em;
    margin: 0 0 8px;
}

h2 {
    margin-top: 32px;
}

h3 {
    margin-top: 24px;
}

.meta {
    color: var(--muted);
}

.grid {
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(145px, 1fr)
        );
    gap: 14px;
    margin: 22px 0 36px;
}

.card,
.finding {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
}

.metric {
    font-size: 2rem;
    font-weight: 800;
}

.label {
    color: var(--muted);
    font-size: .78rem;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.finding {
    margin: 18px 0;
}

.finding-header {
    display: flex;
    justify-content: space-between;
    gap: 20px;
    align-items: flex-start;
}

.finding-header h2 {
    margin: 4px 0 0;
}

.finding-id {
    color: var(--muted);
    font-size: .8rem;
    font-weight: 700;
    letter-spacing: .08em;
    text-transform: uppercase;
}

.finding-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 18px;
    margin: 14px 0 18px;
    color: var(--muted);
    font-size: .9rem;
}

.badge {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    background: var(--panel2);
    font-weight: 800;
    white-space: nowrap;
}

.kev {
    font-weight: 800;
}

code {
    background: var(--panel2);
    padding: 2px 6px;
    border-radius: 6px;
}

pre {
    overflow: auto;
    background: #050b14;
    border: 1px solid var(--border);
    padding: 16px;
    border-radius: 12px;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0 30px;
}

th,
td {
    text-align: left;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
}

th {
    color: var(--muted);
    font-size: .82rem;
    text-transform: uppercase;
    letter-spacing: .06em;
}

.summary-section {
    margin-top: 34px;
}

.notice {
    border-left: 3px solid var(--accent);
    padding: 12px 16px;
    background: var(--panel);
    border-radius: 8px;
    color: var(--muted);
}
"""

        return (
            "<!doctype html>"
            '<html lang="en">'
            "<head>"
            '<meta charset="utf-8">'
            '<meta name="viewport" '
            'content="width=device-width,initial-scale=1">'
            f"<title>{escape(title)}</title>"
            f"<style>{css}</style>"
            "</head>"
            "<body>"
            "<main>"
            "<header>"
            f"<h1>{escape(title)}</h1>"
            f'<div class="meta">{escape(subtitle)}</div>'
            "</header>"
            f'<section class="grid">{cards}</section>'
            '<section class="summary-section">'
            "<h2>Assessment Context</h2>"
            "<table>"
            "<tbody>"
            f"<tr><th>Target</th>"
            f"<td>{escape(str(self.report.target))}</td></tr>"
            f"<tr><th>Target Type</th>"
            f"<td>{escape(str(self.report.target_type))}</td></tr>"
            f"<tr><th>Profile</th>"
            f"<td>{escape(str(self.report.profile))}</td></tr>"
            f"<tr><th>Run ID</th>"
            f"<td>{escape(str(self.report.run_id))}</td></tr>"
            f"<tr><th>Started</th>"
            f"<td>{escape(str(self.report.start_time))}</td></tr>"
            f"<tr><th>Finished</th>"
            f"<td>{escape(str(self.report.end_time))}</td></tr>"
            f"<tr><th>Duration</th>"
            f"<td>{self.report.duration_seconds:.2f} seconds</td></tr>"
            "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Risk Summary</h2>"
            "<table>"
            "<thead>"
            "<tr><th>Severity</th><th>Findings</th></tr>"
            "</thead>"
            "<tbody>"
            + "".join(
                (
                    "<tr>"
                    f"<td>{escape(severity)}</td>"
                    f"<td>{counts.get(severity, 0)}</td>"
                    "</tr>"
                )
                for severity in _SEVERITIES
            )
            + "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Attack Surface Summary</h2>"
            "<table>"
            "<tbody>"
            f"<tr><th>Subdomains discovered</th>"
            f"<td>{statistics.subdomains_found}</td></tr>"
            f"<tr><th>Alive hosts</th>"
            f"<td>{statistics.alive_hosts}</td></tr>"
            f"<tr><th>Final hosts</th>"
            f"<td>{statistics.final_hosts}</td></tr>"
            f"<tr><th>URLs discovered</th>"
            f"<td>{statistics.urls_discovered}</td></tr>"
            "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Vulnerability Intelligence</h2>"
            "<table>"
            "<tbody>"
            f"<tr><th>Intelligence observations</th>"
            f"<td>{intelligence['observations']}</td></tr>"
            f"<tr><th>Unique CVEs</th>"
            f"<td>{intelligence['cves']}</td></tr>"
            f"<tr><th>NVD matches</th>"
            f"<td>{intelligence['nvd']}</td></tr>"
            f"<tr><th>KEV matches</th>"
            f"<td>{intelligence['kev']}</td></tr>"
            f"<tr><th>Version-based matches</th>"
            f"<td>{intelligence['version_matches']}</td></tr>"
            "</tbody>"
            "</table>"
            '<div class="notice">'
            "NVD/CVE intelligence represents potential exposure and "
            "does not independently confirm target-specific "
            "exploitability."
            "</div>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Software Assessments</h2>"
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Product</th>"
            "<th>Version</th>"
            "<th>Vendor</th>"
            "<th>CPE</th>"
            "<th>Confidence</th>"
            "<th>NVD Checked</th>"
            "<th>Applicable CVEs</th>"
            "<th>KEV</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
            + (
                "".join(
                    (
                        "<tr>"
                        f"<td>{escape(str(data.get('product') or '—'))}</td>"
                        f"<td>{escape(str(data.get('version') or '—'))}</td>"
                        f"<td>{escape(str(data.get('vendor') or '—'))}</td>"
                        f"<td><code>{escape(str(data.get('cpe') or '—'))}</code></td>"
                        f"<td>{escape(str(data.get('confidence') or '—'))}</td>"
                        f"<td>{'Yes' if data.get('nvd_checked') else 'No'}</td>"
                        f"<td>{data.get('applicable_cve_count', 0)}</td>"
                        f"<td>{data.get('kev_count', 0)}</td>"
                        "</tr>"
                    )
                    for data in (
                        self._software_assessment_data(
                            assessment
                        )
                        for assessment in getattr(
                            self.report,
                            "software_assessments",
                            [],
                        )
                    )
                )
                or (
                    "<tr>"
                    '<td colspan="8">No software assessments recorded.</td>'
                    "</tr>"
                )
            )
            + "</tbody>"
            + "</table>"
            + '<div class="notice">'
            "Software assessments represent identified software components "
            "evaluated against NVD/CVE intelligence. A zero-CVE assessment "
            "is informational and is not a confirmed vulnerability."
            "</div>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Tool Coverage</h2>"
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Tool</th>"
            "<th>Status</th>"
            "<th>Findings</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
            + "".join(
                tool_rows
            )
            + "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Assessment Stages</h2>"
            "<table>"
            "<thead>"
            "<tr><th>Stage</th><th>Status</th></tr>"
            "</thead>"
            "<tbody>"
            + "".join(
                stage_rows
            )
            + "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Native ScopeForgeX Analysis</h2>"
            "<table>"
            "<thead>"
            "<tr>"
            "<th>Analyzer</th>"
            "<th>Results</th>"
            "<th>Findings</th>"
            "</tr>"
            "</thead>"
            "<tbody>"
            + "".join(
                native_rows
            )
            + "</tbody>"
            "</table>"
            "</section>"
            '<section class="summary-section">'
            "<h2>Security Findings</h2>"
            f"{finding_html}"
            "</section>"
            '<section class="summary-section">'
            "<h2>Evidence & Report Status</h2>"
            "<table>"
            "<tbody>"
            f"<tr><th>Evidence references</th>"
            f"<td>{len(self.report.evidence_references)}</td></tr>"
            f"<tr><th>Finding evidence references</th>"
            f"<td>{len(self.report.finding_evidence_references)}</td></tr>"
            f"<tr><th>Correlated evidence references</th>"
            f"<td>{len(self.report.correlated_evidence_references)}</td></tr>"
            f"<tr><th>Warnings</th>"
            f"<td>{len(self.report.warnings)}</td></tr>"
            f"<tr><th>Errors</th>"
            f"<td>{len(self.report.errors)}</td></tr>"
            f"<tr><th>Generated files</th>"
            f"<td>{len(self.report.generated_files)}</td></tr>"
            f"<tr><th>Schema version</th>"
            f"<td>{escape(str(self.report.schema_version))}</td></tr>"
            "</tbody>"
            "</table>"
            "</section>"
            "</main>"
            "</body>"
            "</html>"
        )

    def generate_professional_html(
        self,
        output_file: str,
    ) -> None:
        path = Path(
            output_file
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            self._html(
                "ScopeForgeX Security Assessment Report",
                (
                    f"{self.report.target} · "
                    f"{self.report.profile} · "
                    f"run {self.report.run_id}"
                ),
            ),
            encoding="utf-8",
        )

    def generate_findings_html(
        self,
        output_file: str,
    ) -> None:
        path = Path(
            output_file
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            self._html(
                "ScopeForgeX Findings Report",
                (
                    f"{self.report.target} · "
                    f"{self.report.profile} · "
                    "findings-oriented view"
                ),
            ),
            encoding="utf-8",
        )


__all__ = [
    "ReportGenerator",
]
