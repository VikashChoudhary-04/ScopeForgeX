"""
ScopeForgeX Runtime Enums
=========================

Canonical enumerations used by the ScopeForgeX runtime.

These enums provide stable values for:

- Assessment workflow phases
- Execution status
- Finding severity
- Finding confidence

Keeping these values centralized prevents individual stages, tools,
collectors, analyzers and reporting components from defining incompatible
phase, status, severity or confidence names.

v1.1.0
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
    Canonical ScopeForgeX assessment phases.

    The ordering represents the normal assessment lifecycle.
    """

    RECONNAISSANCE = "reconnaissance"

    ENUMERATION = "enumeration"

    VULNERABILITY_ASSESSMENT = (
        "vulnerability_assessment"
    )

    EXPLOITATION = "exploitation"

    POST_EXPLOITATION = (
        "post_exploitation"
    )

    REPORTING = "reporting"


def get_phase_order(
    phase: AssessmentPhase,
) -> int:
    """
    Return the canonical execution order for an assessment phase.

    Lower values execute earlier in the workflow.
    """

    order = {
        AssessmentPhase.RECONNAISSANCE: 1,
        AssessmentPhase.ENUMERATION: 2,
        AssessmentPhase.VULNERABILITY_ASSESSMENT: 3,
        AssessmentPhase.EXPLOITATION: 4,
        AssessmentPhase.POST_EXPLOITATION: 5,
        AssessmentPhase.REPORTING: 6,
    }

    return order[phase]


def get_phase_order_map() -> dict[AssessmentPhase, int]:
    """
    Return the complete canonical assessment phase ordering.
    """

    return {
        AssessmentPhase.RECONNAISSANCE: 1,
        AssessmentPhase.ENUMERATION: 2,
        AssessmentPhase.VULNERABILITY_ASSESSMENT: 3,
        AssessmentPhase.EXPLOITATION: 4,
        AssessmentPhase.POST_EXPLOITATION: 5,
        AssessmentPhase.REPORTING: 6,
    }


###############################################################################
# Execution Status
###############################################################################


class ExecutionStatus(
    str,
    Enum,
):
    """
    Canonical status values for tool and stage execution.
    """

    PENDING = "pending"

    RUNNING = "running"

    SUCCESS = "success"

    FAILED = "failed"

    SKIPPED = "skipped"


###############################################################################
# Finding Severity
###############################################################################


class Severity(
    str,
    Enum,
):
    """
    Canonical finding severity values.

    INFO is intentionally included because not every assessment result is a
    vulnerability. Informational observations such as discovered services,
    technologies and attack-surface details can still be meaningful findings.
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
    Canonical confidence values for assessment findings.

    Detection confidence is intentionally separate from severity.

    A high-severity detection does not automatically mean that the finding
    has been manually confirmed.
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
