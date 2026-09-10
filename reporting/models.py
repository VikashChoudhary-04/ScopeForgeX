"""
ScopeForgeX Reporting Models
============================

Canonical data structures for ScopeForgeX assessment findings and reports.

The universal Finding model is the common representation used after tool
collection, native analysis, specialized validation, correlation and
deduplication.

Assessment pipeline
-------------------

Tool / Analyzer
        |
        v
Collector / Analyzer Observation
        |
        v
Finding Normalization
        |
        v
Canonical Finding
        |
        +--> Correlation
        |
        +--> Deduplication
        |
        +--> Risk Classification
        |
        +--> Evidence Management
        |
        v
Professional Reporting

Design Principles
-----------------

- Every finding uses one universal structure.
- Detection is not automatically confirmation.
- Confidence is separate from severity.
- Source-tool information is preserved.
- Detection method is preserved.
- Evidence is preserved independently from finding metadata.
- CWE/CVE information is retained when available.
- Manual findings use the same model as automated findings.
- Reporting consumes normalized findings rather than raw scanner output.
- Raw tool output remains assessment evidence.
- The model supports the complete ScopeForgeX assessment lifecycle.

v1.3.0
"""

from __future__ import annotations

from dataclasses import (
    asdict,
    dataclass,
    field,
)
from datetime import datetime
from typing import Any

from scopeforgex.intelligence.models import SoftwareAssessment

from scopeforgex.runtime import AssessmentPhase


###############################################################################
# Finding Evidence
###############################################################################


@dataclass
class FindingEvidence:
    """
    Evidence attached to a ScopeForgeX finding.

    Evidence represents material supporting a detection. It may originate
    from an external tool, a native analyzer, a specialized validator or a
    manual analyst.
    """

    description: str = ""

    request: str = ""

    response: str = ""

    screenshot: str = ""

    file_path: str = ""

    raw_output: str = ""

    artifact_path: str = ""

    source: str = ""

    details: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def metadata(self) -> dict[str, Any]:
        """
        Compatibility alias for older callers.
        """

        return self.details

    @metadata.setter
    def metadata(
        self,
        value: dict[str, Any],
    ) -> None:
        self.details = value

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize finding evidence.
        """

        return asdict(
            self
        )


###############################################################################
# Universal Finding
###############################################################################


@dataclass
class Finding:
    """
    Universal normalized ScopeForgeX finding.

    A Finding represents an assessment observation that has been normalized
    into the canonical reporting model. Detection and validation remain
    separate concepts.
    """

    finding_id: str

    title: str

    category: str = "security_issue"

    severity: str = "Informational"

    confidence: str = "Medium"

    status: str = "Pending"

    target: str = ""

    host: str | None = None

    port: int | None = None

    url: str | None = None

    parameter: str | None = None

    description: str = ""

    impact: str = ""

    remediation: str = ""

    evidence: FindingEvidence = field(
        default_factory=FindingEvidence,
    )

    source_tool: str = ""

    detection_method: str = ""

    timestamp: datetime | str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    cwe: str | None = None

    cve: str | None = None

    references: list[str] = field(
        default_factory=list,
    )

    @property
    def source(self) -> str:
        """
        Compatibility alias for source_tool.
        """

        return self.source_tool

    @source.setter
    def source(
        self,
        value: str,
    ) -> None:
        self.source_tool = str(
            value
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the complete universal finding model.
        """

        data = asdict(
            self
        )

        if isinstance(
            self.timestamp,
            datetime,
        ):
            data["timestamp"] = (
                self.timestamp.isoformat()
            )

        return data


###############################################################################
# Severity Models
###############################################################################


@dataclass
class SeveritySummary:
    """
    Distribution of findings by severity.
    """

    critical: int = 0

    high: int = 0

    medium: int = 0

    low: int = 0

    informational: int = 0

    def total(
        self,
    ) -> int:
        """
        Return the total number of findings.
        """

        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.informational
        )

    def as_dict(
        self,
    ) -> dict[str, int]:
        """
        Serialize the severity summary.
        """

        return asdict(
            self
        )


###############################################################################
# Tool Execution Models
###############################################################################


@dataclass
class ToolExecutionResult:
    """
    Individual external-tool execution record.

    This represents execution metadata, not the normalized finding itself.
    """

    tool: str

    stage: str

    status: str

    findings: int = 0

    duration: float = 0.0

    artifacts: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the execution record.
        """

        return asdict(
            self
        )


###############################################################################
# Assessment Phase Models
###############################################################################


@dataclass
class StageResult:
    """
    Assessment-phase result.

    The class name is retained for compatibility with existing reporting
    callers. The canonical lifecycle identifier is AssessmentPhase.
    """

    phase: AssessmentPhase

    status: str

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the stage result.
        """

        return {
            "phase": self.phase.value,
            "status": self.status,
        }


###############################################################################
# Workflow Statistics
###############################################################################


@dataclass
class ScanStatistics:
    """
    Assessment execution and coverage statistics.
    """

    subdomains_found: int = 0

    alive_hosts: int = 0

    final_hosts: int = 0

    urls_discovered: int = 0

    nuclei_findings: int = 0

    files_generated: int = 0

    tools_executed: int = 0

    stages_executed: int = 0

    stages_skipped: int = 0

    findings_total: int = 0

    findings_critical: int = 0

    findings_high: int = 0

    findings_medium: int = 0

    findings_low: int = 0

    findings_informational: int = 0

    findings_confirmed: int = 0

    findings_pending: int = 0

    findings_false_positive: int = 0

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize assessment statistics.
        """

        return asdict(
            self
        )


###############################################################################
# Report Metadata
###############################################################################


@dataclass
class ReportMetadata:
    """
    Metadata describing the generated assessment report.
    """

    generator: str = "ScopeForgeX"

    version: str = "v1.3.0"

    generated_by: str = (
        "ScopeForgeX Reporting Engine"
    )


###############################################################################
# Complete Report
###############################################################################


@dataclass
class ReportData:
    """
    Complete ScopeForgeX assessment report object.

    ReportData is the canonical structured state consumed by all report
    presentation and export layers.

    The object retains both normalized findings and the assessment-wide
    state required to reproduce the professional report, findings-oriented
    report and machine-readable JSON report without maintaining a second
    independent report representation.
    """

    target: str

    profile: str

    target_type: str

    start_time: datetime

    end_time: datetime

    statistics: ScanStatistics

    generated_files: list[str] = field(
        default_factory=list,
    )

    stages: list[StageResult] = field(
        default_factory=list,
    )

    findings: list[Finding] = field(
        default_factory=list,
    )

    tool_results: dict[str, str] = field(
        default_factory=dict,
    )

    metadata: ReportMetadata = field(
        default_factory=ReportMetadata,
    )

    warnings: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    duration_seconds: float = 0.0

    # Assessment identity.
    run_id: str = ""

    schema_version: str = "4.0"

    # Correlation and normalized assessment state.
    correlation_groups: list[Any] = field(
        default_factory=list,
    )

    correlated_findings: list[Any] = field(
        default_factory=list,
    )

    # Collection and execution state.
    collector_results: list[Any] = field(
        default_factory=list,
    )

    execution_results: list[Any] = field(
        default_factory=list,
    )

    # Native and external vulnerability intelligence.
    native_analyzer_results: list[Any] = field(
        default_factory=list,
    )

    vulnerability_intelligence_results: list[Any] = field(
        default_factory=list,
    )

    software_assessments: list[SoftwareAssessment] = field(
        default_factory=list,
    )

    # Evidence state.
    evidence_references: list[Any] = field(
        default_factory=list,
    )

    raw_evidence_references: list[Any] = field(
        default_factory=list,
    )

    finding_evidence_references: list[Any] = field(
        default_factory=list,
    )

    correlated_evidence_references: list[Any] = field(
        default_factory=list,
    )

    # Canonical report-level derived state.
    summary: dict[str, Any] = field(
        default_factory=dict,
    )

    vulnerability_intelligence: dict[str, Any] = field(
        default_factory=dict,
    )

    analysis_metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    # Presentation metadata.
    report_views: dict[str, Any] = field(
        default_factory=dict,
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the complete report into JSON-compatible data.

        The field names intentionally preserve the canonical Stage 6 JSON
        contract so existing consumers continue to receive the same
        assessment-wide information.
        """

        return {
            "target": self.target,

            "profile": self.profile,

            "target_type": self.target_type,

            "run_id": self.run_id,

            "schema_version": self.schema_version,

            "start_time": (
                self.start_time.isoformat()
                if isinstance(
                    self.start_time,
                    datetime,
                )
                else self.start_time
            ),

            "end_time": (
                self.end_time.isoformat()
                if isinstance(
                    self.end_time,
                    datetime,
                )
                else self.end_time
            ),

            "duration_seconds": (
                self.duration_seconds
            ),

            "statistics": (
                self.statistics.as_dict()
                if hasattr(
                    self.statistics,
                    "as_dict",
                )
                else self.statistics
            ),

            "generated_files": list(
                self.generated_files
            ),

            "stages": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.stages
            ],

            "findings": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.findings
            ],

            "correlation_groups": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.correlation_groups
            ],

            "correlated_findings": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.correlated_findings
            ],

            "collector_results": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.collector_results
            ],

            "execution_results": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.execution_results
            ],

            "native_analyzer_results": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.native_analyzer_results
            ],

            "vulnerability_intelligence_results": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.vulnerability_intelligence_results
            ],

            "software_assessments": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.software_assessments
            ],

            "evidence_references": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.evidence_references
            ],

            "raw_evidence_references": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.raw_evidence_references
            ],

            "finding_evidence_references": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.finding_evidence_references
            ],

            "correlated_evidence_references": [
                item.as_dict()
                if hasattr(
                    item,
                    "as_dict",
                )
                else item
                for item in self.correlated_evidence_references
            ],

            "summary": dict(
                self.summary
            ),

            "vulnerability_intelligence": dict(
                self.vulnerability_intelligence
            ),

            "analysis_metadata": dict(
                self.analysis_metadata
            ),

            "report_views": dict(
                self.report_views
            ),

            "tool_results": dict(
                self.tool_results
            ),

            "metadata": asdict(
                self.metadata
            ),

            "warnings": list(
                self.warnings
            ),

            "errors": list(
                self.errors
            ),
        }


###############################################################################
# Public API
###############################################################################


__all__ = [
    "FindingEvidence",
    "Finding",
    "SeveritySummary",
    "ToolExecutionResult",
    "StageResult",
    "ScanStatistics",
    "ReportMetadata",
    "ReportData",
]
