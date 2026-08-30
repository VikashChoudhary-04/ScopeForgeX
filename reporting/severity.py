"""
ScopeForgeX Severity & Normalization
====================================

Canonical normalization helpers for:

- Finding severity
- Finding confidence
- Finding validation status

The reporting layer uses these helpers to ensure that findings originating
from external tools, native analyzers, validators, correlation logic and
manual analysts use a consistent vocabulary.

Design Principles
-----------------

- Severity represents technical/business impact.
- Confidence represents strength of supporting evidence.
- Status represents finding validation lifecycle.
- Input values are normalized into canonical ScopeForgeX values.
- Unknown values fail safely into conservative defaults.
- Normalization is deterministic and case-insensitive.

Canonical Severity Values
--------------------------

    Critical
    High
    Medium
    Low
    Informational

Canonical Confidence Values
---------------------------

    Confirmed
    High
    Medium
    Low

Canonical Finding Status Values
--------------------------------

    Confirmed
    Pending
    False Positive

v1.3.0
"""

from __future__ import annotations


###############################################################################
# Canonical Values
###############################################################################


CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
INFORMATIONAL = "Informational"


CONFIRMED = "Confirmed"
PENDING = "Pending"
FALSE_POSITIVE = "False Positive"


###############################################################################
# Severity Normalization
###############################################################################


def normalize_severity(
    value: object,
) -> str:
    """
    Normalize a severity value into the canonical ScopeForgeX vocabulary.

    Parameters
    ----------
    value:
        Severity value supplied by a scanner, analyzer, collector or analyst.

    Returns
    -------
    str
        One of:

        - Critical
        - High
        - Medium
        - Low
        - Informational

    Unknown or missing values are treated as Informational.
    """

    if value is None:
        return INFORMATIONAL

    normalized = str(
        value
    ).strip().lower()

    if not normalized:
        return INFORMATIONAL

    aliases = {
        "critical": CRITICAL,
        "crit": CRITICAL,

        "high": HIGH,
        "hi": HIGH,

        "medium": MEDIUM,
        "moderate": MEDIUM,
        "med": MEDIUM,

        "low": LOW,
        "lo": LOW,

        "informational": INFORMATIONAL,
        "information": INFORMATIONAL,
        "info": INFORMATIONAL,
        "informative": INFORMATIONAL,
        "none": INFORMATIONAL,
        "unknown": INFORMATIONAL,
    }

    return aliases.get(
        normalized,
        INFORMATIONAL,
    )


###############################################################################
# Confidence Normalization
###############################################################################


def normalize_confidence(
    value: object,
) -> str:
    """
    Normalize a confidence value into the canonical ScopeForgeX vocabulary.

    Parameters
    ----------
    value:
        Confidence supplied by a scanner, analyzer, validator or analyst.

    Returns
    -------
    str
        One of:

        - Confirmed
        - High
        - Medium
        - Low

    Unknown or missing values are treated as Medium.
    """

    if value is None:
        return MEDIUM

    normalized = str(
        value
    ).strip().lower()

    if not normalized:
        return MEDIUM

    aliases = {
        "confirmed": CONFIRMED,
        "confirm": CONFIRMED,
        "verified": CONFIRMED,
        "validated": CONFIRMED,

        "high": HIGH,
        "hi": HIGH,
        "strong": HIGH,

        "medium": MEDIUM,
        "moderate": MEDIUM,
        "med": MEDIUM,

        "low": LOW,
        "lo": LOW,
        "weak": LOW,

        "unknown": MEDIUM,
    }

    return aliases.get(
        normalized,
        MEDIUM,
    )


###############################################################################
# Finding Status Normalization
###############################################################################


def normalize_finding_status(
    value: object,
) -> str:
    """
    Normalize a finding validation status.

    Parameters
    ----------
    value:
        Status supplied by a collector, validator, correlation engine or
        analyst.

    Returns
    -------
    str
        One of:

        - Confirmed
        - Pending
        - False Positive

    Unknown or missing values are treated as Pending.
    """

    if value is None:
        return PENDING

    normalized = str(
        value
    ).strip().lower()

    if not normalized:
        return PENDING

    aliases = {
        "confirmed": CONFIRMED,
        "confirm": CONFIRMED,
        "verified": CONFIRMED,
        "validated": CONFIRMED,
        "true positive": CONFIRMED,
        "true_positive": CONFIRMED,

        "pending": PENDING,
        "unconfirmed": PENDING,
        "unknown": PENDING,
        "review": PENDING,
        "needs review": PENDING,
        "needs_review": PENDING,

        "false positive": FALSE_POSITIVE,
        "false_positive": FALSE_POSITIVE,
        "false-positive": FALSE_POSITIVE,
        "fp": FALSE_POSITIVE,
        "false": FALSE_POSITIVE,
    }

    return aliases.get(
        normalized,
        PENDING,
    )


###############################################################################
# Severity Ordering
###############################################################################


SEVERITY_ORDER: dict[str, int] = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFORMATIONAL: 1,
}


def severity_rank(
    value: object,
) -> int:
    """
    Return the numeric rank of a severity.

    Higher values represent greater severity.
    """

    normalized = normalize_severity(
        value
    )

    return SEVERITY_ORDER[
        normalized
    ]


def higher_severity(
    first: object,
    second: object,
) -> str:
    """
    Return the higher of two severity values.
    """

    first_normalized = normalize_severity(
        first
    )

    second_normalized = normalize_severity(
        second
    )

    if (
        severity_rank(first_normalized)
        >= severity_rank(second_normalized)
    ):
        return first_normalized

    return second_normalized


###############################################################################
# Public API
###############################################################################


__all__ = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
    "CONFIRMED",
    "PENDING",
    "FALSE_POSITIVE",
    "SEVERITY_ORDER",
    "normalize_severity",
    "normalize_confidence",
    "normalize_finding_status",
    "severity_rank",
    "higher_severity",
]
