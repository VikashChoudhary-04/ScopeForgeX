"""
ScopeForgeX Severity Engine
===========================

Severity classification and risk calculation engine.

v0.6.0

Responsibilities:
    - Normalize severity values
    - Map CVSS scores to severity
    - Calculate severity distribution
    - Calculate overall risk rating
"""

from __future__ import annotations

from reporting.models import (
    Finding,
    SeveritySummary,
)


###############################################################################
# Severity Constants
###############################################################################


SEVERITY_LEVELS = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


###############################################################################
# Normalization
###############################################################################


def normalize_severity(
    severity: str | None,
) -> str:
    """
    Normalize severity labels.
    """

    if not severity:

        return "Informational"


    value = (
        severity
        .strip()
        .lower()
    )


    mapping = {

        "critical":
            "Critical",

        "crit":
            "Critical",

        "high":
            "High",

        "medium":
            "Medium",

        "moderate":
            "Medium",

        "med":
            "Medium",

        "low":
            "Low",

        "info":
            "Informational",

        "informational":
            "Informational",

    }


    return mapping.get(
        value,
        "Informational",
    )



###############################################################################
# CVSS Mapping
###############################################################################


def cvss_to_severity(
    score: float | None,
) -> str:
    """
    Convert CVSS score into severity.
    """

    if score is None:

        return "Informational"


    if score >= 9.0:

        return "Critical"


    if score >= 7.0:

        return "High"


    if score >= 4.0:

        return "Medium"


    if score > 0:

        return "Low"


    return "Informational"



###############################################################################
# Summary Calculation
###############################################################################


def calculate_summary(
    findings: list[Finding],
) -> SeveritySummary:
    """
    Build severity distribution.
    """

    summary = SeveritySummary()


    for finding in findings:

        severity = normalize_severity(
            finding.severity
        )


        if severity == "Critical":

            summary.critical += 1


        elif severity == "High":

            summary.high += 1


        elif severity == "Medium":

            summary.medium += 1


        elif severity == "Low":

            summary.low += 1


        else:

            summary.informational += 1


    return summary



###############################################################################
# Risk Rating
###############################################################################


def calculate_risk_rating(
    summary: SeveritySummary,
) -> str:
    """
    Calculate overall assessment risk.
    """

    if summary.critical > 0:

        return "Critical"


    if summary.high > 0:

        return "High"


    if summary.medium > 0:

        return "Medium"


    if summary.low > 0:

        return "Low"


    return "Informational"



###############################################################################
# Finding Helpers
###############################################################################


def apply_cvss_severity(
    finding: Finding,
) -> Finding:
    """
    Update finding severity from CVSS.
    """

    if finding.cvss is not None:

        finding.severity = (
            cvss_to_severity(
                finding.cvss
            )
        )


    else:

        finding.severity = (
            normalize_severity(
                finding.severity
            )
        )


    return finding



###############################################################################
# Public API
###############################################################################


__all__ = [

    "SEVERITY_LEVELS",

    "normalize_severity",

    "cvss_to_severity",

    "calculate_summary",

    "calculate_risk_rating",

    "apply_cvss_severity",

]
