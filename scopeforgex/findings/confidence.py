"""
ScopeForgeX Finding Confidence
==============================

Confidence classification and management for the universal ScopeForgeX
Finding model.

Confidence answers:

    "How confident are we that this observation is accurate?"

It does NOT answer:

    "How severe is this finding?"

and it does NOT automatically answer:

    "Has this vulnerability been manually confirmed?"

Confidence is therefore independent from severity.

Confidence Levels
-----------------

Confirmed
    The finding has been explicitly validated or confirmed by an analyst or
    an authorized validation process.

High
    Strong, reliable detection with sufficient supporting evidence, but without
    explicit manual confirmation.

Medium
    A credible detection or scanner result that requires additional
    investigation or validation.

Low
    A weak, incomplete, or potentially ambiguous observation.

Informational
    An observation where confidence is not meaningfully represented as a
    security claim, or where the result is purely contextual.

Design Principles
-----------------

- Confidence is independent from severity.
- Detection does not automatically mean confirmation.
- Scanner output must not automatically become Confirmed.
- Explicit validation may promote a finding to Confirmed.
- Rejected findings must never be promoted by this module.
- Confidence classification is deterministic.
- This module never performs network requests.
- This module never executes external tools.
- This module does not calculate severity or risk.
- Existing Finding objects are updated in place when requested.
- The module remains independent from reporting.

Architecture
------------

Collector / Analyzer
        |
        v
Finding
        |
        v
Confidence Assessment
        |
        +--> Low
        +--> Medium
        +--> High
        +--> Confirmed
        +--> Informational
        |
        v
Risk Classification / Reporting

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .model import (
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_HIGH,
    CONFIDENCE_INFORMATIONAL,
    CONFIDENCE_LEVELS,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    STATUS_CONFIRMED,
    STATUS_REJECTED,
    Finding,
)


###############################################################################
# Constants
###############################################################################


DEFAULT_CONFIDENCE = CONFIDENCE_MEDIUM

CONFIDENCE_ORDER = (
    CONFIDENCE_INFORMATIONAL,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH,
    CONFIDENCE_CONFIRMED,
)

VALID_CONFIDENCES = frozenset(
    CONFIDENCE_LEVELS
)

# Confidence aliases accepted at the public API boundary.
_CONFIDENCE_ALIASES = {
    "info": CONFIDENCE_INFORMATIONAL,
    "informational": CONFIDENCE_INFORMATIONAL,
    "low": CONFIDENCE_LOW,
    "medium": CONFIDENCE_MEDIUM,
    "moderate": CONFIDENCE_MEDIUM,
    "high": CONFIDENCE_HIGH,
    "confirmed": CONFIDENCE_CONFIRMED,
    "verified": CONFIDENCE_CONFIRMED,
}


###############################################################################
# Normalization
###############################################################################


def normalize_confidence(
    value: Any,
    *,
    default: str = DEFAULT_CONFIDENCE,
) -> str:
    """
    Normalize a confidence value to the canonical ScopeForgeX value.

    Args:
        value:
            Confidence value supplied by a collector, analyzer, validator,
            configuration layer, or caller.

        default:
            Value returned when the supplied value is empty or unsupported.

    Returns:
        One of the canonical confidence levels.

    Examples:
        >>> normalize_confidence("high")
        'High'

        >>> normalize_confidence("verified")
        'Confirmed'

        >>> normalize_confidence(None)
        'Medium'
    """

    normalized_default = _canonical_confidence(
        default
    )

    if value is None:
        return normalized_default

    if hasattr(
        value,
        "value",
    ):
        value = value.value

    text = str(
        value
    ).strip()

    if not text:
        return normalized_default

    return _CONFIDENCE_ALIASES.get(
        text.lower(),
        normalized_default,
    )


def is_valid_confidence(
    value: Any,
) -> bool:
    """
    Return whether a value represents a canonical confidence level.
    """

    if value is None:
        return False

    if hasattr(
        value,
        "value",
    ):
        value = value.value

    text = str(
        value
    ).strip()

    return (
        text in VALID_CONFIDENCES
    )


def _canonical_confidence(
    value: Any,
) -> str:
    """
    Normalize a confidence value and fall back to the default.

    Internal helper used where a canonical value is required.
    """

    if value is None:
        return DEFAULT_CONFIDENCE

    if hasattr(
        value,
        "value",
    ):
        value = value.value

    text = str(
        value
    ).strip()

    if text in VALID_CONFIDENCES:
        return text

    return _CONFIDENCE_ALIASES.get(
        text.lower(),
        DEFAULT_CONFIDENCE,
    )


###############################################################################
# Confidence Levels
###############################################################################


def confidence_level(
    value: Any,
) -> int:
    """
    Return the numeric strength of a confidence value.

    Higher values represent stronger confidence.

    Returns:
        Integer from 0 through 4.
    """

    normalized = normalize_confidence(
        value
    )

    return CONFIDENCE_LEVELS[
        normalized
    ]


def stronger_confidence(
    first: Any,
    second: Any,
) -> str:
    """
    Return the stronger of two confidence values.

    This operation only compares confidence. It does not independently
    validate either finding.
    """

    first_normalized = normalize_confidence(
        first
    )

    second_normalized = normalize_confidence(
        second
    )

    if (
        confidence_level(
            second_normalized
        )
        > confidence_level(
            first_normalized
        )
    ):
        return second_normalized

    return first_normalized


def confidence_at_least(
    value: Any,
    minimum: Any,
) -> bool:
    """
    Return whether a confidence value meets or exceeds a minimum level.
    """

    return (
        confidence_level(
            value
        )
        >= confidence_level(
            minimum
        )
    )


###############################################################################
# Explicit Validation
###############################################################################


def is_explicitly_confirmed(
    finding: Finding,
) -> bool:
    """
    Determine whether a Finding contains an explicit confirmation signal.

    Confirmation is deliberately conservative.

    A finding is considered explicitly confirmed when:

    - its confidence is already Confirmed, or
    - its status is Confirmed.

    Source tool, severity, evidence quantity, or scanner name alone never
    establishes confirmation.
    """

    _require_finding(
        finding
    )

    confidence = normalize_confidence(
        finding.confidence
    )

    if confidence == CONFIDENCE_CONFIRMED:
        return True

    status = str(
        getattr(
            finding,
            "status",
            "",
        )
    ).strip().lower()

    return (
        status == STATUS_CONFIRMED.lower()
    )


###############################################################################
# Classification
###############################################################################


def classify_confidence(
    finding: Finding,
    *,
    explicit_confirmation: bool = False,
    default: str = DEFAULT_CONFIDENCE,
) -> str:
    """
    Determine an appropriate confidence level for a Finding.

    The classifier is intentionally conservative.

    Rules
    -----

    1. Rejected findings remain Low.
    2. Explicit confirmation produces Confirmed.
    3. Existing Confirmed confidence is preserved.
    4. Existing High/Medium/Low/Informational confidence is preserved.
    5. Missing confidence falls back to Medium.

    Importantly, this function does not infer confirmation merely because:

    - the source is Nuclei,
    - the source is Nmap NSE,
    - evidence exists,
    - severity is High/Critical,
    - multiple tools reported the issue.

    Those signals may be useful to correlation or future assessment logic, but
    they do not constitute explicit vulnerability confirmation.
    """

    _require_finding(
        finding
    )

    status = str(
        getattr(
            finding,
            "status",
            "",
        )
    ).strip().lower()

    if status == STATUS_REJECTED.lower():
        return CONFIDENCE_LOW

    current = normalize_confidence(
        getattr(
            finding,
            "confidence",
            None,
        ),
        default=default,
    )

    if (
        explicit_confirmation
        or is_explicitly_confirmed(
            finding
        )
    ):
        return CONFIDENCE_CONFIRMED

    return current


def classify_observation(
    *,
    source_tool: str = "",
    evidence: Any = None,
    validated: bool = False,
    confidence: Any = None,
    default: str = DEFAULT_CONFIDENCE,
) -> str:
    """
    Classify a newly produced observation.

    This helper is intended for collectors and analyzers before a Finding has
    necessarily been constructed.

    Rules
    -----

    - Explicit validation -> Confirmed.
    - Explicit caller-supplied confidence -> normalized supplied value.
    - Otherwise -> Medium.

    Source tool and evidence are accepted as context but are deliberately not
    sufficient to promote a result to High or Confirmed automatically.

    This keeps the important distinction:

        Detection != Confirmation.
    """

    del source_tool
    del evidence

    if validated:
        return CONFIDENCE_CONFIRMED

    if confidence is not None:
        return normalize_confidence(
            confidence,
            default=default,
        )

    return normalize_confidence(
        default
    )


###############################################################################
# Finding Operations
###############################################################################


def apply_confidence(
    finding: Finding,
    confidence: Any,
    *,
    allow_confirmation: bool = False,
) -> Finding:
    """
    Apply a confidence value to an existing Finding.

    Args:
        finding:
            Canonical ScopeForgeX Finding.

        confidence:
            Desired confidence level.

        allow_confirmation:
            Explicitly permits setting Confirmed confidence. This should only
            be used when the caller has an actual validation basis.

    Returns:
        The same Finding object.

    Raises:
        TypeError:
            If finding is not a Finding.

        ValueError:
            If an attempt is made to assign Confirmed without explicit
            confirmation permission.
    """

    _require_finding(
        finding
    )

    normalized = normalize_confidence(
        confidence
    )

    if (
        normalized == CONFIDENCE_CONFIRMED
        and not allow_confirmation
        and not is_explicitly_confirmed(
            finding
        )
    ):
        raise ValueError(
            "Confirmed confidence requires explicit validation."
        )

    finding.confidence = normalized

    return finding


def confirm_finding(
    finding: Finding,
    *,
    status: bool = True,
    validation_method: str | None = None,
    notes: str | None = None,
) -> Finding:
    """
    Explicitly confirm or unconfirm a Finding.

    This function represents an analyst or authorized validation action.

    Args:
        finding:
            Canonical ScopeForgeX Finding.

        status:
            True confirms the finding. False removes the explicit confirmation
            state and restores Medium confidence unless a previous confidence
            is supplied separately.

        validation_method:
            Optional description of how the finding was validated.

        notes:
            Optional analyst validation notes.

    Returns:
        The same Finding object.

    Notes:
        This function does not perform validation itself. It records the
        result of validation performed elsewhere.
    """

    _require_finding(
        finding
    )

    metadata = _ensure_metadata(
        finding
    )

    if status:
        finding.confidence = (
            CONFIDENCE_CONFIRMED
        )

        finding.status = (
            STATUS_CONFIRMED
        )

        metadata[
            "validation_status"
        ] = "confirmed"

        if validation_method:
            metadata[
                "validation_method"
            ] = str(
                validation_method
            ).strip()

        if notes:
            metadata[
                "validation_notes"
            ] = str(
                notes
            ).strip()

    else:
        # Removing confirmation must not silently claim that the finding is
        # rejected. It simply returns it to a pending/medium-confidence state.
        finding.confidence = (
            CONFIDENCE_MEDIUM
        )

        if str(
            getattr(
                finding,
                "status",
                "",
            )
        ).strip().lower() == STATUS_CONFIRMED.lower():
            metadata[
                "previous_status"
            ] = finding.status

        finding.status = "Pending"

        metadata[
            "validation_status"
        ] = "pending"

    return finding


def downgrade_confidence(
    finding: Finding,
    confidence: Any,
) -> Finding:
    """
    Lower a Finding's confidence without allowing accidental promotion.

    The requested confidence must be weaker than the current confidence.

    This is useful when later analysis identifies uncertainty in an earlier
    observation.
    """

    _require_finding(
        finding
    )

    requested = normalize_confidence(
        confidence
    )

    current = normalize_confidence(
        finding.confidence
    )

    if (
        confidence_level(
            requested
        )
        > confidence_level(
            current
        )
    ):
        raise ValueError(
            "downgrade_confidence() cannot increase confidence."
        )

    finding.confidence = requested

    if requested != CONFIDENCE_CONFIRMED:
        status = str(
            getattr(
                finding,
                "status",
                "",
            )
        ).strip().lower()

        if status == STATUS_CONFIRMED.lower():
            finding.status = "Pending"

    return finding


###############################################################################
# Batch Operations
###############################################################################


def apply_confidence_many(
    findings: Iterable[Finding],
    confidence: Any,
    *,
    allow_confirmation: bool = False,
) -> list[Finding]:
    """
    Apply one confidence level to multiple Findings.
    """

    if findings is None:
        return []

    result: list[Finding] = []

    for finding in findings:
        result.append(
            apply_confidence(
                finding,
                confidence,
                allow_confirmation=allow_confirmation,
            )
        )

    return result


def classify_findings(
    findings: Iterable[Finding],
) -> list[Finding]:
    """
    Normalize and apply confidence classification to a collection of Findings.

    Existing explicit confirmation is preserved.

    No new confirmation is inferred.
    """

    if findings is None:
        return []

    result: list[Finding] = []

    for finding in findings:
        _require_finding(
            finding
        )

        finding.confidence = (
            classify_confidence(
                finding
            )
        )

        result.append(
            finding
        )

    return result


###############################################################################
# Confidence Summary
###############################################################################


def confidence_summary(
    findings: Iterable[Finding],
) -> dict[str, int]:
    """
    Return a count of Findings grouped by confidence level.

    The result always contains every canonical confidence level so reporting
    code can consume it deterministically.
    """

    summary = {
        confidence: 0
        for confidence in CONFIDENCE_ORDER
    }

    if findings is None:
        return summary

    for finding in findings:
        _require_finding(
            finding
        )

        confidence = normalize_confidence(
            finding.confidence
        )

        summary[
            confidence
        ] += 1

    return summary


def highest_confidence(
    findings: Iterable[Finding],
) -> str:
    """
    Return the strongest confidence represented by a collection.

    Empty collections return Informational.
    """

    if findings is None:
        return CONFIDENCE_INFORMATIONAL

    highest = CONFIDENCE_INFORMATIONAL

    for finding in findings:
        _require_finding(
            finding
        )

        current = normalize_confidence(
            finding.confidence
        )

        if (
            confidence_level(
                current
            )
            > confidence_level(
                highest
            )
        ):
            highest = current

    return highest


###############################################################################
# Metadata Helpers
###############################################################################


def record_validation_metadata(
    finding: Finding,
    *,
    validation_status: str,
    validation_method: str | None = None,
    notes: str | None = None,
) -> Finding:
    """
    Record validation metadata without automatically changing confidence.

    This is useful when validation has started but has not yet established
    confirmation.

    Examples of validation states:

        pending
        confirmed
        rejected

    The caller should use ``confirm_finding()`` when validation actually
    establishes confirmation.
    """

    _require_finding(
        finding
    )

    metadata = _ensure_metadata(
        finding
    )

    normalized_status = str(
        validation_status
    ).strip().lower()

    if not normalized_status:
        raise ValueError(
            "validation_status cannot be empty."
        )

    metadata[
        "validation_status"
    ] = normalized_status

    if validation_method:
        metadata[
            "validation_method"
        ] = str(
            validation_method
        ).strip()

    if notes:
        metadata[
            "validation_notes"
        ] = str(
            notes
        ).strip()

    return finding


def _ensure_metadata(
    finding: Finding,
) -> dict[str, Any]:
    """
    Ensure a Finding has a mutable metadata dictionary.
    """

    metadata = getattr(
        finding,
        "metadata",
        None,
    )

    if metadata is None:
        metadata = {}
        finding.metadata = metadata

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = dict(
            metadata
        )
        finding.metadata = metadata

    return metadata


###############################################################################
# Input Validation
###############################################################################


def _require_finding(
    finding: Any,
) -> None:
    """
    Validate that an object is the canonical ScopeForgeX Finding type.
    """

    if not isinstance(
        finding,
        Finding,
    ):
        raise TypeError(
            "Confidence operations require a "
            "scopeforgex.findings.model.Finding object."
        )


###############################################################################
# Convenience API
###############################################################################


def get_confidence(
    finding: Finding,
) -> str:
    """
    Return the canonical confidence value of a Finding.
    """

    _require_finding(
        finding
    )

    return normalize_confidence(
        finding.confidence
    )


def set_confidence(
    finding: Finding,
    confidence: Any,
    *,
    allow_confirmation: bool = False,
) -> Finding:
    """
    Convenience wrapper around apply_confidence().
    """

    return apply_confidence(
        finding,
        confidence,
        allow_confirmation=allow_confirmation,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "DEFAULT_CONFIDENCE",
    "CONFIDENCE_ORDER",
    "VALID_CONFIDENCES",
    "normalize_confidence",
    "is_valid_confidence",
    "confidence_level",
    "stronger_confidence",
    "confidence_at_least",
    "is_explicitly_confirmed",
    "classify_confidence",
    "classify_observation",
    "apply_confidence",
    "confirm_finding",
    "downgrade_confidence",
    "apply_confidence_many",
    "classify_findings",
    "confidence_summary",
    "highest_confidence",
    "record_validation_metadata",
    "get_confidence",
    "set_confidence",
]
