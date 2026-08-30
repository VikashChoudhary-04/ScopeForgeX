"""
ScopeForgeX Runtime Enumerations
================================

Canonical runtime enums and phase ordering for ScopeForgeX 3.0.0.

The assessment lifecycle is:

    Scope Authorization
        ↓
    Reconnaissance
        ↓
    Enumeration
        ↓
    Vulnerability Assessment
        ↓
    Vulnerability Validation
        ↓
    Credential Assessment
        ↓
    Reporting

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from enum import Enum


###############################################################################
# Assessment Phase
###############################################################################


class AssessmentPhase(
    str,
    Enum,
):
    """
    Canonical ScopeForgeX assessment lifecycle.

    These phases describe workflow purpose rather than individual
    implementations or tools.
    """

    SCOPE_AUTHORIZATION = (
        "scope_authorization"
    )

    RECONNAISSANCE = (
        "reconnaissance"
    )

    ENUMERATION = (
        "enumeration"
    )

    VULNERABILITY_ASSESSMENT = (
        "vulnerability_assessment"
    )

    VULNERABILITY_VALIDATION = (
        "vulnerability_validation"
    )

    CREDENTIAL_ASSESSMENT = (
        "credential_assessment"
    )

    REPORTING = (
        "reporting"
    )


###############################################################################
# Assessment Phase Compatibility
###############################################################################


# Compatibility alias retained for code that previously used AssessmentPhase.SCOPE.
#
# This does not create another enum member.
AssessmentPhase.SCOPE = (
    AssessmentPhase.SCOPE_AUTHORIZATION
)


def get_phase_order() -> tuple[AssessmentPhase, ...]:
    """
    Return the canonical ScopeForgeX assessment phase execution order.

    Reporting is always last.
    """

    return (
        AssessmentPhase.SCOPE_AUTHORIZATION,
        AssessmentPhase.RECONNAISSANCE,
        AssessmentPhase.ENUMERATION,
        AssessmentPhase.VULNERABILITY_ASSESSMENT,
        AssessmentPhase.VULNERABILITY_VALIDATION,
        AssessmentPhase.CREDENTIAL_ASSESSMENT,
        AssessmentPhase.REPORTING,
    )


def get_phase_order_map() -> dict[AssessmentPhase, int]:
    """
    Return the canonical numeric ordering of assessment phases.
    """

    return {
        AssessmentPhase.SCOPE_AUTHORIZATION: 1,
        AssessmentPhase.RECONNAISSANCE: 2,
        AssessmentPhase.ENUMERATION: 3,
        AssessmentPhase.VULNERABILITY_ASSESSMENT: 4,
        AssessmentPhase.VULNERABILITY_VALIDATION: 5,
        AssessmentPhase.CREDENTIAL_ASSESSMENT: 6,
        AssessmentPhase.REPORTING: 7,
    }


###############################################################################
# Execution Status
###############################################################################


class ExecutionStatus(
    str,
    Enum,
):
    """
    Canonical execution status values.
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


###############################################################################
# Finding Severity
###############################################################################


class Severity(
    str,
    Enum,
):
    """
    Canonical finding severity values.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


###############################################################################
# Finding Confidence
###############################################################################


class Confidence(
    str,
    Enum,
):
    """
    Canonical finding confidence values.

    Confidence is intentionally separate from severity. A high-severity
    detection is not automatically a manually confirmed finding.
    """

    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


###############################################################################
# Public API
###############################################################################


__all__ = [
    "AssessmentPhase",
    "ExecutionStatus",
    "Severity",
    "Confidence",
    "get_phase_order",
    "get_phase_order_map",
]
