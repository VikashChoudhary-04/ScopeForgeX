"""
ScopeForgeX Findings Package
============================

Universal finding model and finding-processing components for ScopeForgeX.

The findings package provides the structured layer between raw tool output
and professional assessment reporting.

Architecture
------------

Raw Tool Output
    |
    v
Collectors / Normalizers
    |
    v
Finding
    |
    +--> Deduplication
    |
    +--> Correlation
    |
    +--> Risk / Confidence
    |
    +--> Evidence
    |
    v
Report Generator

Core Components
---------------

Finding
    Universal normalized security-assessment finding model.

FindingNormalizer
    Converts supported observations into canonical Finding objects.

FindingDeduplicator
    Removes repeated representations of the same finding while preserving
    useful evidence and provenance.

FindingCorrelator
    Relates distinct findings that belong to the same asset, service, or
    endpoint context.

The package deliberately keeps these responsibilities separate:

    Normalization
        Convert observations into a common schema.

    Deduplication
        Remove duplicate representations.

    Correlation
        Identify relationships between distinct findings.

    Reporting
        Present the resulting assessment information professionally.

Design Principles
-----------------

- Findings are structured assessment objects, not raw scanner output.
- Detection does not automatically mean confirmation.
- Confidence is distinct from severity.
- Evidence is preserved.
- Source-tool provenance is preserved.
- Deduplication is deterministic.
- Correlation is deterministic and conservative.
- Finding processing does not execute external tools.
- Finding processing does not perform network requests.
- Human validation remains possible through finding status and confidence.
- The package is independent from the CLI and workflow implementation.

Public API
----------

The package exposes the primary finding-processing interfaces so callers can
use:

    from scopeforgex.findings import Finding
    from scopeforgex.findings import FindingNormalizer
    from scopeforgex.findings import FindingDeduplicator
    from scopeforgex.findings import FindingCorrelator

Convenience functions are also exported where available.

v1.2.0
"""

from __future__ import annotations

###############################################################################
# Finding Model
###############################################################################

from .model import (
    CONFIDENCE_LEVELS,
    SEVERITY_LEVELS,
    Finding,
)

###############################################################################
# Normalization
###############################################################################

from .normalizer import (
    FindingNormalizer,
    normalize_finding,
    normalize_findings,
)

###############################################################################
# Deduplication
###############################################################################

from .deduplicator import (
    FindingDeduplicator,
    deduplicate_findings,
    findings_are_duplicates,
)

###############################################################################
# Correlation
###############################################################################

from .correlation import (
    ASSET_RELATIONSHIP,
    ENDPOINT_RELATIONSHIP,
    PARAMETER_RELATIONSHIP,
    REFERENCE_RELATIONSHIP,
    SERVICE_RELATIONSHIP,
    TOOL_RELATIONSHIP,
    CorrelationGroup,
    FindingCorrelator,
    correlate_findings,
)

###############################################################################
# Public API
###############################################################################

__all__ = [
    # Finding model
    "Finding",
    "SEVERITY_LEVELS",
    "CONFIDENCE_LEVELS",

    # Normalization
    "FindingNormalizer",
    "normalize_finding",
    "normalize_findings",

    # Deduplication
    "FindingDeduplicator",
    "deduplicate_findings",
    "findings_are_duplicates",

    # Correlation relationship types
    "ASSET_RELATIONSHIP",
    "SERVICE_RELATIONSHIP",
    "ENDPOINT_RELATIONSHIP",
    "PARAMETER_RELATIONSHIP",
    "REFERENCE_RELATIONSHIP",
    "TOOL_RELATIONSHIP",

    # Correlation
    "CorrelationGroup",
    "FindingCorrelator",
    "correlate_findings",
]
