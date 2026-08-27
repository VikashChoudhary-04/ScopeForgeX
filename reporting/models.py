"""
ScopeForgeX Reporting Models
============================

Canonical reporting data structures.

v1.1.0

Supports:
    - Professional pentest reports
    - Vulnerability findings
    - Evidence tracking
    - Tool execution summaries
    - Severity aggregation
    - Assessment-phase reporting
    - Runtime execution statistics
    - JSON serialization
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
# Finding Models
###############################################################################


@dataclass
class FindingEvidence:
    """
    Evidence attached to a vulnerability finding.
    """

    description: str = ""

    request: str = ""

    response: str = ""

    screenshot: str = ""

    file_path: str = ""

    def as_dict(
        self,
    ) -> dict[str, Any]:

        return asdict(
            self
        )


@dataclass
class Finding:
    """
    Normalized vulnerability finding.

    All vulnerability sources should eventually
    convert into this format.
    """

    finding_id: str

    title: str

    severity: str

    target: str

    source: str

    description: str = ""

    impact: str = ""

    remediation: str = ""

    evidence: FindingEvidence = field(
        default_factory=FindingEvidence,
    )

    cvss: float | None = None

    references: list[str] = field(
        default_factory=list,
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:

        data = asdict(
            self
        )

        data["evidence"] = (
            self.evidence.as_dict()
        )

        return data


###############################################################################
# Severity Models
###############################################################################


@dataclass
class SeveritySummary:
    """
    Vulnerability severity distribution.
    """

    critical: int = 0

    high: int = 0

    medium: int = 0

    low: int = 0

    informational: int = 0

    def total(
        self,
    ) -> int:

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

        return asdict(
            self
        )


###############################################################################
# Tool Execution Models
###############################################################################


@dataclass
class ToolExecutionResult:
    """
    Individual tool execution record.
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

    The class name is retained for compatibility with existing
    reporting callers. The canonical lifecycle identifier is
    AssessmentPhase.
    """

    phase: AssessmentPhase

    status: str

    def as_dict(
        self,
    ) -> dict[str, Any]:

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
    Workflow and assessment statistics.

    RuntimeState is the authoritative source for execution history.
    These fields expose the relevant execution totals to reporting.
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


###############################################################################
# Report Metadata
###############################################################################


@dataclass
class ReportMetadata:
    """
    Additional report information.
    """

    generator: str = "ScopeForgeX"

    version: str = "v1.1.0"

    generated_by: str = "ScopeForgeX Reporting Engine"


###############################################################################
# Complete Report
###############################################################################


@dataclass
class ReportData:
    """
    Complete assessment report object.
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

            "start_time": (
                self.start_time.isoformat()
            ),

            "end_time": (
                self.end_time.isoformat()
            ),

            "duration_seconds": (
                self.duration_seconds
            ),

            "statistics": asdict(
                self.statistics
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
