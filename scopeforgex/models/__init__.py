"""
ScopeForgeX Models
==================

Canonical data models and normalization primitives used throughout
ScopeForgeX.

The models package provides the normalized boundary between execution,
collection, analysis, correlation, risk classification, evidence handling,
and reporting.

Architecture
------------

Execution / Collector / Analyzer
        |
        v
    Finding Model
        |
        +--> Adapters
        |
        +--> Correlation
        |
        v
   Downstream Pipeline

Public Components
-----------------

Finding
    Universal ScopeForgeX assessment finding.

FindingEvidence
    Structured evidence container associated with a finding.

ExecutionResult
    Canonical result returned by executable tools.

Finding Adapters
    Normalize collector and native analyzer observations into Finding
    objects.

Finding Correlation
    Group related normalized findings without merging or deleting them.

Design Principles
-----------------

- Models contain data and deterministic normalization behavior.
- Models do not execute external tools.
- Models do not perform network requests.
- Models remain independent from reporting.
- Findings remain independent from execution results.
- Correlation does not perform deduplication.
- Adapters do not perform correlation or risk classification.
- Original assessment information remains recoverable.

v1.3.0
"""

from __future__ import annotations


###############################################################################
# Finding Model
###############################################################################

from scopeforgex.models.finding import (
    DEFAULT_CATEGORY,
    DEFAULT_CONFIDENCE,
    DEFAULT_SEVERITY,
    DEFAULT_STATUS,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_PENDING,
    Finding,
    FindingEvidence,
    utc_now as finding_utc_now,
)


###############################################################################
# Finding Adapters
###############################################################################

from scopeforgex.models.adapters import (
    collector_observation_to_finding,
    mapping_to_finding,
    normalize_observations,
    observation_id,
)


###############################################################################
# Finding Correlation
###############################################################################

from scopeforgex.models.correlation import (
    ASSET_RELATIONSHIP,
    ENDPOINT_RELATIONSHIP,
    PARAMETER_RELATIONSHIP,
    REFERENCE_RELATIONSHIP,
    SERVICE_RELATIONSHIP,
    TOOL_RELATIONSHIP,
    CorrelationGroup,
    FindingCorrelator,
    correlate_by_asset,
    correlate_by_endpoint,
    correlate_by_parameter,
    correlate_by_service,
    correlate_findings,
)


###############################################################################
# Execution Result
###############################################################################

from scopeforgex.models.execution_result import (
    ExecutionResult,
    utc_now as execution_utc_now,
)


###############################################################################
# Public API
###############################################################################

__all__ = [
    # Finding
    "Finding",
    "FindingEvidence",
    "DEFAULT_CATEGORY",
    "DEFAULT_SEVERITY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_STATUS",
    "FINDING_STATUS_PENDING",
    "FINDING_STATUS_CONFIRMED",
    "finding_utc_now",

    # Adapters
    "collector_observation_to_finding",
    "mapping_to_finding",
    "normalize_observations",
    "observation_id",

    # Correlation
    "CorrelationGroup",
    "FindingCorrelator",
    "ASSET_RELATIONSHIP",
    "SERVICE_RELATIONSHIP",
    "ENDPOINT_RELATIONSHIP",
    "PARAMETER_RELATIONSHIP",
    "REFERENCE_RELATIONSHIP",
    "TOOL_RELATIONSHIP",
    "correlate_findings",
    "correlate_by_asset",
    "correlate_by_service",
    "correlate_by_endpoint",
    "correlate_by_parameter",

    # Execution
    "ExecutionResult",
    "execution_utc_now",
]
