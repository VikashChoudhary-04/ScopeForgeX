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


def _finding_data(finding: Any) -> dict[str, Any]:
    if isinstance(finding, dict):
        return dict(finding)
    if hasattr(finding, "as_dict"):
        try:
            value = finding.as_dict()
            if isinstance(value, dict):
                return dict(value)
        except Exception:
            pass
    return {}


def _severity(finding: Any) -> str:
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


def _title(finding: Any) -> str:
    return str(
        _finding_data(finding).get(
            "title",
            "Untitled Finding",
        )
    )


def _asset(finding: Any) -> str:
    data = _finding_data(finding)
    for key in ("url", "host", "target"):
        value = data.get(key)
        if value:
            return str(value)
    return "Unspecified"


def _cve(finding: Any) -> str:
    data = _finding_data(finding)

    value = data.get("cve")
    if value:
        return str(value)

    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        for item in metadata.get("cves", []) or []:
            if str(item).strip():
                return str(item).strip()

    return ""


def _intelligence_summary(report: ReportData) -> dict[str, int]:
    """Summarize NVD/CVE/KEV intelligence attached to the report."""
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
        data = _finding_data(record)
        cve = data.get("cve")
        if cve:
            cves.add(str(cve).strip())
        metadata = data.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        kev += int(metadata.get("kev") is True)
        nvd += int(
            metadata.get("intelligence_source") == "NVD"
            or data.get("source_tool") == "NVD"
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


class ReportGenerator:
    """Generate the two human-facing report views from ReportData."""

    def __init__(
        self,
        report: ReportData,
    ) -> None:
        self.report = report

    def _sorted_findings(self) -> list[Any]:
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
                _title(finding).lower(),
            )
        )

        return findings

    def _severity_counts(self) -> dict[str, int]:
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

        lines = [
            f"### {finding_id} — {_title(finding)}",
            "",
            "| Severity | Confidence | Validation | Source |",
            "|---|---|---|---|",
            (
                f"| **{_severity(finding)}** | "
                f"{data.get('confidence', 'Informational')} | "
                f"{data.get('status', 'Open')} | "
                f"{data.get('source_tool', 'ScopeForgeX')} |"
            ),
            "",
            f"**Affected Asset:** `{_asset(finding)}`",
            "",
        ]

        cve = _cve(finding)
        if cve:
            lines.extend(
                [
                    f"**CVE:** `{cve}`",
                    "",
                ]
            )

        for heading, key in (
            ("Description", "description"),
            ("Impact", "impact"),
            ("Remediation", "remediation"),
        ):
            value = data.get(key)
            if value:
                lines.extend(
                    [
                        f"**{heading}**",
                        "",
                        str(value),
                        "",
                    ]
                )

        evidence = data.get("evidence")
        if evidence:
            lines.extend(
                [
                    "**Evidence**",
                    "",
                    "```json",
                    json.dumps(
                        evidence,
                        indent=2,
                        ensure_ascii=False,
                        default=str,
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
        """Compatibility alias for the Professional Markdown report."""
        self.generate_professional_markdown(
            output_file
        )

    def generate_professional_markdown(
        self,
        output_file: str,
    ) -> None:
        findings = self._sorted_findings()
        counts = self._severity_counts()

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
            f"- **Run ID:** `{getattr(self.report, 'run_id', '')}`",
            f"- **Duration:** `{self.report.duration_seconds:.2f} seconds`",
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
                "## 2. Assessment Scope",
                "",
                f"- **Target:** `{self.report.target}`",
                f"- **Target Type:** `{self.report.target_type}`",
                f"- **Started:** `{self.report.start_time}`",
                f"- **Finished:** `{self.report.end_time}`",
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
                f"{getattr(self.report.statistics, 'subdomains_found', 0)}",
                f"- **Alive hosts:** "
                f"{getattr(self.report.statistics, 'alive_hosts', 0)}",
                f"- **Final hosts:** "
                f"{getattr(self.report.statistics, 'final_hosts', 0)}",
                f"- **URLs discovered:** "
                f"{getattr(self.report.statistics, 'urls_discovered', 0)}",
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
                _finding_data(finding).get(
                    "status",
                    "Open",
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
                _finding_data(finding).get(
                    "source_tool",
                    "ScopeForgeX",
                )
            )
            for finding in findings
        )

        for tool, status in self.report.tool_results.items():
            lines.append(
                f"| {tool} | `{status}` | "
                f"{source_counts.get(tool, 0)} |"
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

        native_counts: dict[str, list[int]] = {}

        for result in self.report.native_analyzer_results:
            if hasattr(result, "as_dict"):
                data = result.as_dict()
            elif isinstance(result, dict):
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

        lines.extend(
            [
                "",
                "## 14. Appendix",
                "",
                f"- **Warnings:** {len(self.report.warnings)}",
                f"- **Errors:** {len(self.report.errors)}",
                f"- **Generated files:** {len(self.report.generated_files)}",
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

        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        path.write_text(
            "\n".join(lines).rstrip() + "\n",
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
                _cve(finding)
                for finding in findings
                if _cve(finding)
            }
        )

        intelligence = _intelligence_summary(
            self.report
        )

        assets = sorted(
            {
                _asset(finding)
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
            f"| Informational | **{counts.get('Informational', 0)}** |",
            f"| CVEs | **{len(cves)}** |",
            f"| Affected assets | **{len(assets)}** |",
            f"| NVD matches | **{intelligence['nvd']}** |",
            f"| KEV matches | **{intelligence['kev']}** |",
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
                cve = _cve(finding)
                if not cve:
                    continue
                data = _finding_data(finding)
                lines.append(
                    f"| `{cve}` | {_severity(finding)} | "
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
                    f"| `{asset}` | {asset_counts[asset]} |"
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
                f"- **Profile:** `{self.report.profile}`",
                f"- **Run ID:** `{getattr(self.report, 'run_id', '')}`",
                "",
            ]
        )

        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        path.write_text(
            "\n".join(lines).rstrip() + "\n",
            encoding="utf-8",
        )

    def _html(
        self,
        title: str,
        subtitle: str,
    ) -> str:
        findings = self._sorted_findings()
        counts = self._severity_counts()

        card_items = [
            ("Findings", len(findings)),
            ("Critical", counts.get("Critical", 0)),
            ("High", counts.get("High", 0)),
            ("Medium", counts.get("Medium", 0)),
            (
                "CVEs",
                len(
                    {
                        _cve(finding)
                        for finding in findings
                        if _cve(finding)
                    }
                ),
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

        rendered_findings = []

        for finding in findings:
            data = _finding_data(finding)
            cve = _cve(finding)

            pieces = [
                '<article class="finding">',
                (
                    f"<h2>{escape(_title(finding))}</h2>"
                ),
                (
                    '<span class="badge">'
                    f"{escape(_severity(finding))}</span>"
                ),
                (
                    f"<p><strong>Affected:</strong> "
                    f"<code>{escape(_asset(finding))}</code></p>"
                ),
            ]

            if cve:
                pieces.append(
                    f"<p><strong>CVE:</strong> "
                    f"<code>{escape(cve)}</code></p>"
                )

            source = data.get(
                "source_tool",
                "ScopeForgeX",
            )

            pieces.append(
                f"<p><strong>Source:</strong> "
                f"{escape(str(source))}</p>"
            )

            description = data.get(
                "description"
            )

            if description:
                pieces.append(
                    f"<p>{escape(str(description))}</p>"
                )

            evidence = data.get(
                "evidence"
            )

            if evidence:
                pieces.append(
                    "<pre>"
                    + escape(
                        json.dumps(
                            evidence,
                            indent=2,
                            default=str,
                        )
                    )
                    + "</pre>"
                )

            pieces.append(
                "</article>"
            )

            rendered_findings.append(
                "".join(pieces)
            )

        finding_html = "".join(
            rendered_findings
        )

        if not finding_html:
            finding_html = (
                '<div class="card"><strong>'
                "No findings recorded."
                "</strong></div>"
            )

        css = """
        :root{color-scheme:dark;--bg:#08111f;--panel:#101b2d;
        --panel2:#17263d;--text:#edf4ff;--muted:#9eacc2;
        --border:#2b3d59;--accent:#63b3ff}
        *{box-sizing:border-box}
        body{margin:0;background:linear-gradient(135deg,#07101c,#0b1424);
        color:var(--text);font-family:Inter,system-ui,sans-serif;line-height:1.55}
        main{max-width:1180px;margin:auto;padding:46px 24px 80px}
        h1{font-size:2.35rem;letter-spacing:-.035em;margin:0 0 8px}
        h2{margin-top:32px}.meta{color:var(--muted)}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
        gap:14px;margin:22px 0}
        .card,.finding{background:var(--panel);border:1px solid var(--border);
        border-radius:16px;padding:20px}
        .metric{font-size:2rem;font-weight:800}
        .label{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}
        .finding{margin:18px 0}
        .badge{display:inline-block;padding:4px 9px;border-radius:999px;
        background:var(--panel2);font-weight:800}
        code{background:var(--panel2);padding:2px 6px;border-radius:6px}
        pre{overflow:auto;background:#050b14;border:1px solid var(--border);
        padding:16px;border-radius:12px}
        """

        return (
            "<!doctype html>"
            '<html lang="en">'
            "<head>"
            '<meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
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
            "<h2>Security Findings</h2>"
            f"{finding_html}"
            "</main>"
            "</body>"
            "</html>"
        )

    def generate_professional_html(
        self,
        output_file: str,
    ) -> None:
        path = Path(output_file)
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
                    f"run {getattr(self.report, 'run_id', '')}"
                ),
            ),
            encoding="utf-8",
        )

    def generate_findings_html(
        self,
        output_file: str,
    ) -> None:
        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        path.write_text(
            self._html(
                "ScopeForgeX Findings Report",
                f"{self.report.target} · findings-oriented view",
            ),
            encoding="utf-8",
        )


__all__ = [
    "ReportGenerator",
]
