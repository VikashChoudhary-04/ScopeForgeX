"""
ScopeForgeX Findings Model Compatibility Layer
==============================================

Compatibility exports for the historical ``scopeforgex.findings.model``
module.

The canonical Finding model now lives in:

    scopeforgex.models.finding

This module intentionally does not define a second Finding implementation.
Existing imports from the findings package can continue to resolve while the
rest of the findings subsystem is migrated to the canonical model.

v1.3.0
"""

from __future__ import annotations

from scopeforgex.models.finding import (
    DEFAULT_CATEGORY,
    DEFAULT_CONFIDENCE,
    DEFAULT_SEVERITY,
    DEFAULT_STATUS,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_PENDING,
    Finding,
    FindingEvidence,
    utc_now,
)


###############################################################################
# Compatibility Constants
###############################################################################

# Historical findings.model consumers used the longer severity names.
# The canonical model itself uses the runtime enum values:
#
#     info
#     low
#     medium
#     high
#     critical
#
# These aliases are retained only for import compatibility.

SEVERITY_INFORMATIONAL = DEFAULT_SEVERITY
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"


# Canonical severity ordering.
SEVERITY_LEVELS: dict[str, int] = {
    SEVERITY_INFORMATIONAL: 0,
    SEVERITY_LOW: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_HIGH: 3,
    SEVERITY_CRITICAL: 4,
}


# Canonical confidence values.
CONFIDENCE_INFORMATIONAL = DEFAULT_CONFIDENCE
CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"
CONFIDENCE_CONFIRMED = "confirmed"


# Canonical confidence ordering.
CONFIDENCE_LEVELS: dict[str, int] = {
    CONFIDENCE_INFORMATIONAL: 0,
    CONFIDENCE_LOW: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_HIGH: 3,
    CONFIDENCE_CONFIRMED: 4,
}


# Historical lifecycle constants retained for compatibility with code that
# imports them from findings.model.
STATUS_OPEN = "open"
STATUS_PENDING = FINDING_STATUS_PENDING
STATUS_CONFIRMED = FINDING_STATUS_CONFIRMED
STATUS_REJECTED = "rejected"
STATUS_REMEDIATED = "remediated"
STATUS_ACCEPTED = "accepted"


###############################################################################
# Compatibility Helpers
###############################################################################


def normalize_text(value: object) -> str:
    """
    Normalize a value into stripped text.

    Retained for compatibility with historical findings-model consumers.
    """

    if value is None:
        return ""

    return str(value).strip()


def normalize_optional_text(
    value: object,
) -> str | None:
    """
    Normalize an optional textual value.
    """

    normalized = normalize_text(value)

    return normalized or None


def normalize_references(
    value: object,
) -> list[str]:
    """
    Normalize references into a unique list of strings.

    This helper is retained for compatibility. The canonical Finding model
    performs its own reference normalization internally.
    """

    if value is None:
        return []

    if isinstance(value, str):
        value = value.strip()

        return [value] if value else []

    if isinstance(value, (list, tuple, set)):
        references: list[str] = []

        for item in value:
            normalized = normalize_text(item)

            if normalized and normalized not in references:
                references.append(normalized)

        return references

    normalized = normalize_text(value)

    return [normalized] if normalized else []


###############################################################################
# Compatibility API
###############################################################################


__all__ = [
    # Canonical model.
    "Finding",
    "FindingEvidence",

    # Canonical defaults.
    "DEFAULT_CATEGORY",
    "DEFAULT_SEVERITY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_STATUS",
    "FINDING_STATUS_PENDING",
    "FINDING_STATUS_CONFIRMED",

    # Severity compatibility constants.
    "SEVERITY_INFORMATIONAL",
    "SEVERITY_LOW",
    "SEVERITY_MEDIUM",
    "SEVERITY_HIGH",
    "SEVERITY_CRITICAL",
    "SEVERITY_LEVELS",

    # Confidence compatibility constants.
    "CONFIDENCE_INFORMATIONAL",
    "CONFIDENCE_LOW",
    "CONFIDENCE_MEDIUM",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_CONFIRMED",
    "CONFIDENCE_LEVELS",

    # Lifecycle compatibility constants.
    "STATUS_OPEN",
    "STATUS_PENDING",
    "STATUS_CONFIRMED",
    "STATUS_REJECTED",
    "STATUS_REMEDIATED",
    "STATUS_ACCEPTED",

    # Compatibility helpers.
    "normalize_text",
    "normalize_optional_text",
    "normalize_references",
    "utc_now",
]
