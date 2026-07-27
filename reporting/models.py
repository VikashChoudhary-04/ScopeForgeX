"""
reporting/models.py

Reporting data models for ScopeForgeX.

These dataclasses provide a stable contract between workflow stages and
report generators, allowing Markdown, HTML, PDF, JSON and future output
formats to share the same data source.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


# ----------------------------------------------------------------------
# Finding Summary
# ----------------------------------------------------------------------


@dataclass
class FindingSummary:
    """
    Severity breakdown of automated findings.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0

    @property
    def total(self) -> int:
        return (
            self.critical
            + self.high
            + self.medium
            + self.low
            + self.info
            + self.unknown
        )


# ----------------------------------------------------------------------
# Scan Statistics
# ----------------------------------------------------------------------


@dataclass
class ScanStatistics:
    """
    High-level assessment statistics.
    """

    subdomains_found: int = 0
    alive_hosts: int = 0
    final_hosts: int = 0
    urls_discovered: int = 0
    nuclei_findings: int = 0
    files_generated: int = 0

    stages_executed: int = 0
    stages_skipped: int = 0
    tools_executed: int = 0


# ----------------------------------------------------------------------
# Stage Result
# ----------------------------------------------------------------------


@dataclass
class StageResult:
    """
    Workflow stage execution status.
    """

    name: str
    status: str = "Completed"


# ----------------------------------------------------------------------
# Report Data
# ----------------------------------------------------------------------


@dataclass
class ReportData:
    """
    Complete report model consumed by ReportGenerator.
    """

    # Assessment

    target: str
    profile: str
    target_type: str

    # Timing

    start_time: datetime
    end_time: datetime
    duration_seconds: float = 0.0

    # Metadata

    assessment_id: str = ""
    assessment_type: str = "External Web Assessment"
    workflow_name: str = ""
    scopeforgex_version: str = "v0.4.0"

    # Scope

    authentication: str = "None"
    out_of_scope: str = "None"

    # Environment

    operating_system: str = ""
    python_version: str = ""

    # Statistics

    statistics: ScanStatistics = field(default_factory=ScanStatistics)

    findings: FindingSummary = field(default_factory=FindingSummary)

    # Execution

    stages: List[StageResult] = field(default_factory=list)

    tool_results: Dict[str, str] = field(default_factory=dict)

    # Files

    generated_files: List[str] = field(default_factory=list)

    # Notes

    warnings: List[str] = field(default_factory=list)

    recommendations: List[str] = field(default_factory=list)
