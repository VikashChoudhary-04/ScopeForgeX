"""
ScopeForgeX Reporting
=====================

Canonical reporting package for ScopeForgeX.

The reporting layer is responsible for:

- Universal finding representation
- Finding collection and normalization
- Severity/confidence/status normalization
- Assessment report data models
- Markdown report generation
- JSON report export
- Scanner-output parsing

The reporting package consumes normalized runtime and assessment data while
preserving raw scanner output as evidence and generated artifacts.

v1.3.0
"""

from __future__ import annotations


###############################################################################
# Finding Models
###############################################################################

from .models import (
    Finding,
    FindingEvidence,
    ReportData,
    ReportMetadata,
    ScanStatistics,
    SeveritySummary,
    StageResult,
    ToolExecutionResult,
)


###############################################################################
# Finding Collection
###############################################################################

from .findings import (
    FINDING_ID_PREFIX,
    FindingCollector,
    generate_finding_id,
)


###############################################################################
# Severity / Validation Normalization
###############################################################################

from .severity import (
    CRITICAL,
    FALSE_POSITIVE,
    HIGH,
    INFORMATIONAL,
    LOW,
    MEDIUM,
    PENDING,
    CONFIRMED,
    higher_severity,
    normalize_confidence,
    normalize_finding_status,
    normalize_severity,
    severity_rank,
)


###############################################################################
# Report Generation
###############################################################################

from .report_generator import (
    ReportGenerator,
)

from .json_exporter import (
    JSONReportExporter,
    export_json_report,
)


###############################################################################
# Public API
###############################################################################

__all__ = [
    # Finding models
    "Finding",
    "FindingEvidence",
    "SeveritySummary",

    # Execution models
    "ToolExecutionResult",
    "StageResult",
    "ScanStatistics",

    # Report models
    "ReportMetadata",
    "ReportData",

    # Finding collection
    "FINDING_ID_PREFIX",
    "FindingCollector",
    "generate_finding_id",

    # Severity
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",

    # Confidence / status
    "CONFIRMED",
    "PENDING",
    "FALSE_POSITIVE",

    # Normalization
    "normalize_severity",
    "normalize_confidence",
    "normalize_finding_status",

    # Severity utilities
    "SEVERITY_ORDER",
    "severity_rank",
    "higher_severity",

    # Report generation
    "ReportGenerator",
    "JSONReportExporter",
    "export_json_report",
]
