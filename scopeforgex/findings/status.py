"""
ScopeForgeX Finding Status
==========================

Lifecycle status definitions for ScopeForgeX findings.

Finding status describes where a finding currently stands in the assessment
lifecycle. It is intentionally separate from:

    Severity
        How serious the security condition is.

    Confidence
        How confident ScopeForgeX is that the observation represents the
        reported condition.

    Validation
        Whether the security condition has been manually or otherwise
        independently verified.

Status is therefore a lifecycle property rather than a risk property.

Example
-------

Detected
    |
    v
Pending Validation
    |
    +--> Confirmed
    |
    +--> False Positive
    |
    +--> Accepted Risk
    |
    +--> Informational

The status model allows ScopeForgeX to preserve scanner observations without
claiming that every automated result is a confirmed vulnerability.

Design Principles
-----------------

- Status is explicit and deterministic.
- Status does not determine severity.
- Status does not determine confidence.
- Automated detection should not automatically imply confirmation.
- Manual validation can update lifecycle status.
- Reporting can consume status without implementing status logic itself.
- Status values are stable strings suitable for JSON/report serialization.
- No network requests or external tool execution occur here.

v1.2.0
"""

from __future__ import annotations

from enum import Enum
from typing import Any


###############################################################################
# Finding Status
###############################################################################


class FindingStatus(str, Enum):
    """
    Supported ScopeForgeX finding lifecycle states.
    """

    DETECTED = "Detected"

    PENDING_VALIDATION = "Pending Validation"

    CONFIRMED = "Confirmed"

    FALSE_POSITIVE = "False Positive"

    ACCEPTED_RISK = "Accepted Risk"

    INFORMATIONAL = "Informational"

    REMEDIATED = "Remediated"

    RETESTED = "Retested"


###############################################################################
# Status Groups
###############################################################################


OPEN_STATUSES = frozenset(
    {
        FindingStatus.DETECTED,
        FindingStatus.PENDING_VALIDATION,
    }
)

CONFIRMED_STATUSES = frozenset(
    {
        FindingStatus.CONFIRMED,
        FindingStatus.REMEDIATED,
        FindingStatus.RETESTED,
    }
)

CLOSED_STATUSES = frozenset(
    {
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    }
)


###############################################################################
# Status Helpers
###############################################################################


def normalize_status(
    value: FindingStatus | str | None,
) -> FindingStatus:
    """
    Normalize a status value into FindingStatus.

    Args:
        value:
            FindingStatus instance or case-insensitive status string.

    Returns:
        Normalized FindingStatus.

    Raises:
        ValueError:
            If the supplied status is empty or unsupported.
    """

    if isinstance(
        value,
        FindingStatus,
    ):
        return value

    if value is None:
        raise ValueError(
            "Finding status cannot be None."
        )

    normalized = str(
        value
    ).strip()

    if not normalized:
        raise ValueError(
            "Finding status cannot be empty."
        )

    for status in FindingStatus:

        if normalized.lower() in {
            status.value.lower(),
            status.name.lower(),
        }:
            return status

    raise ValueError(
        f"Unsupported finding status: {value!r}"
    )


def is_open_status(
    value: FindingStatus | str,
) -> bool:
    """
    Return whether a finding remains open in the assessment lifecycle.
    """

    return normalize_status(
        value
    ) in OPEN_STATUSES


def is_confirmed_status(
    value: FindingStatus | str,
) -> bool:
    """
    Return whether a finding has reached a confirmed lifecycle state.

    This indicates lifecycle state only. It does not independently prove that
    the underlying security issue is technically valid.
    """

    return normalize_status(
        value
    ) in CONFIRMED_STATUSES


def is_closed_status(
    value: FindingStatus | str,
) -> bool:
    """
    Return whether a finding is closed without remaining an open issue.
    """

    return normalize_status(
        value
    ) in CLOSED_STATUSES


def status_label(
    value: FindingStatus | str,
) -> str:
    """
    Return the human-readable status label.
    """

    return normalize_status(
        value
    ).value


def status_name(
    value: FindingStatus | str,
) -> str:
    """
    Return the stable enum name for a status.
    """

    return normalize_status(
        value
    ).name


###############################################################################
# Serialization
###############################################################################


def status_as_dict(
    value: FindingStatus | str,
) -> dict[str, Any]:
    """
    Serialize a finding status into a structured mapping.
    """

    status = normalize_status(
        value
    )

    return {
        "name": status.name,
        "value": status.value,
        "open": status in OPEN_STATUSES,
        "confirmed": status in CONFIRMED_STATUSES,
        "closed": status in CLOSED_STATUSES,
    }


###############################################################################
# Public API
###############################################################################


__all__ = [
    # Enum
    "FindingStatus",

    # Status groups
    "OPEN_STATUSES",
    "CONFIRMED_STATUSES",
    "CLOSED_STATUSES",

    # Helpers
    "normalize_status",
    "is_open_status",
    "is_confirmed_status",
    "is_closed_status",
    "status_label",
    "status_name",
    "status_as_dict",
]
