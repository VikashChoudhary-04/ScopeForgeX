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

    # Compatibility alias used by existing collectors.
    @property
    def metadata(
        self,
    ) -> dict[str, Any]:
        """
        Backward-compatible alias for details.
        """

        return self.details

    @metadata.setter
    def metadata(
        self,
        value: dict[str, Any],
    ) -> None:
        self.details = dict(
            value or {}
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize evidence into a JSON-compatible dictionary.
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
    Universal ScopeForgeX finding representation.

    Every automated or manual finding should ultimately be represented by
    this model.

    Severity
        How serious the issue is.

    Confidence
        How strongly the available evidence supports the detection.

    Status
        Whether the finding has been validated or remains pending.
    """

    # ========================================================================
    # Identity
    # ========================================================================

    finding_id: str

    title: str

    category: str = "security_issue"

    # ========================================================================
    # Risk / Validation
    # ========================================================================

    severity: str = "Informational"

    confidence: str = "Medium"

    status: str = "Pending"

    # ========================================================================
    # Affected Asset
    # ========================================================================

    target: str = ""

    host: str | None = None

    port: int | None = None

    url: str | None = None

    parameter: str | None = None

    # ========================================================================
    # Finding Description
    # ========================================================================

    description: str = ""

    impact: str = ""

    remediation: str = ""

    # ========================================================================
    # Evidence
    # ========================================================================

    evidence: FindingEvidence = field(
        default_factory=FindingEvidence,
    )

    # ========================================================================
    # Detection Metadata
    # ========================================================================

    source_tool: str = ""

    detection_method: str = ""

    timestamp: datetime | str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    # ========================================================================
    # Security References
    # ========================================================================

    cwe: str | None = None

    cve: str | None = None

    references: list[str] = field(
        default_factory=list,
    )

    # ========================================================================
    # Compatibility
    # ========================================================================

    @property
    def source(
        self,
    ) -> str:
        """
        Backward-compatible alias for source_tool.
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

    The report contains normalized findings rather than raw scanner output as
    its primary result. Raw output remains available through finding evidence
    and generated assessment artifacts.
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

    # Assessment-wide state retained for the canonical report contract.
    run_id: str = ""
    schema_version: str = "4.0"
    correlation_groups: list[Any] = field(
        default_factory=list,
    )
    native_analyzer_results: list[Any] = field(
        default_factory=list,
    )
    vulnerability_intelligence_results: list[Any] = field(
        default_factory=list,
    )
    evidence_references: list[Any] = field(
        default_factory=list,
    )
    finding_evidence_references: list[Any] = field(
        default_factory=list,
    )
    correlated_evidence_references: list[Any] = field(
        default_factory=list,
    )
    report_views: dict[str, Any] = field(
        default_factory=dict,
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the complete report into JSON-compatible data.
        """

        return {
            "target": self.target,

            "profile": self.profile,

            "target_type": self.target_type,

            "run_id": self.run_id,

            "schema_version": self.schema_version,

            "start_time": (
                self.start_time.isoformat()
            ),

            "end_time": (
                self.end_time.isoformat()
            ),

            "duration_seconds": (
                self.duration_seconds
            ),

            "statistics": (
                self.statistics.as_dict()
            ),

            "generated_files": list(
                self.generated_files
            ),

            "stages": [
                stage.as_dict()
                for stage in self.stages
            ],

            "findings": [
                finding.as_dict()
                for finding in self.findings
            ],

            "correlation_groups": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.correlation_groups
            ],

            "native_analyzer_results": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.native_analyzer_results
            ],

            "vulnerability_intelligence_results": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.vulnerability_intelligence_results
            ],

            "evidence_references": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.evidence_references
            ],

            "finding_evidence_references": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.finding_evidence_references
            ],

            "correlated_evidence_references": [
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
                for item in self.correlated_evidence_references
            ],

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
