"""
ScopeForgeX Finding Validator
=============================

Validation orchestration layer for the universal ScopeForgeX Finding model.

The validator records and evaluates explicit analyst validation decisions
against canonical Findings. It provides a consistent interface for marking
findings as pending, confirmed, or rejected without changing the underlying
Finding architecture.

Responsibilities
----------------

- Validate canonical Finding objects.
- Record explicit validation decisions.
- Preserve analyst validation notes.
- Track validation timestamps.
- Update confidence and lifecycle status consistently.
- Provide validation summaries.
- Support batch validation.
- Keep validation independent from correlation and deduplication.

The validator does not:

- Execute arbitrary external tools.
- Perform network requests automatically.
- Invent vulnerability evidence.
- Deduplicate findings.
- Correlate findings.
- Generate reports.
- Replace Finding objects.

Architecture
------------

Canonical Finding
        |
        v
FindingValidator
        |
        +--> Pending
        +--> Confirmed
        +--> Rejected
        |
        v
Canonical Finding
        |
        +--> Correlation
        +--> Deduplication
        +--> Risk
        +--> Reporting

Design Principles
-----------------

- Validation requires an explicit analyst decision.
- Detection does not imply confirmation.
- Validation state is preserved in Finding metadata.
- Existing Finding instances are updated in place.
- Validation does not silently alter severity.
- Validation history is preserved when possible.
- Invalid validation states fail explicitly.
- The validator never performs network activity.
- The validator remains independent from reporting.

v1.3.0
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from scopeforgex.models.finding import Finding
from scopeforgex.runtime.enums import Confidence


###############################################################################
# Constants
###############################################################################

VALIDATION_PENDING = "pending"
VALIDATION_CONFIRMED = "confirmed"
VALIDATION_REJECTED = "rejected"

VALIDATION_STATUS_KEY = "validation_status"
VALIDATED_MANUALLY_KEY = "validated_manually"
VALIDATION_TIMESTAMP_KEY = "validation_timestamp"
VALIDATION_NOTES_KEY = "validation_notes"
VALIDATION_HISTORY_KEY = "validation_history"


###############################################################################
# Validation Result
###############################################################################


@dataclass(frozen=True)
class ValidationResult:
    """
    Result describing a validation operation.

    Attributes:
        finding_id:
            Identifier of the validated Finding.

        status:
            Resulting validation status.

        confirmed:
            Whether the Finding was confirmed.

        confidence:
            Resulting Finding confidence.

        finding_status:
            Resulting Finding lifecycle status.

        notes:
            Notes associated with the validation decision.

        timestamp:
            UTC timestamp at which validation was recorded.
    """

    finding_id: str
    status: str
    confirmed: bool
    confidence: str
    finding_status: str
    notes: str = ""
    timestamp: str = ""

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the validation result.
        """

        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "confirmed": self.confirmed,
            "confidence": self.confidence,
            "finding_status": self.finding_status,
            "notes": self.notes,
            "timestamp": self.timestamp,
        }


###############################################################################
# Validation Summary
###############################################################################


@dataclass
class ValidationSummary:
    """
    Aggregate validation statistics.

    The summary contains counts rather than copies of Findings.
    """

    total: int = 0
    pending: int = 0
    confirmed: int = 0
    rejected: int = 0
    unknown: int = 0
    finding_ids: list[str] = field(
        default_factory=list
    )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the validation summary.
        """

        return {
            "total": self.total,
            "pending": self.pending,
            "confirmed": self.confirmed,
            "rejected": self.rejected,
            "unknown": self.unknown,
            "finding_ids": list(
                self.finding_ids
            ),
        }


###############################################################################
# Finding Validator
###############################################################################


class FindingValidator:
    """
    Manage explicit validation decisions for canonical Findings.

    The validator updates Findings in place and stores validation information
    inside their metadata so that the canonical Finding remains the single
    source of truth.
    """

    name = "finding_validator"

    description = (
        "Record explicit analyst validation decisions for canonical "
        "ScopeForgeX findings."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def validate(
        self,
        finding: Finding,
        *,
        status: str = VALIDATION_CONFIRMED,
        notes: str = "",
        timestamp: datetime | None = None,
    ) -> ValidationResult:
        """
        Apply an explicit validation state to a Finding.

        Args:
            finding:
                Canonical Finding to validate.

            status:
                One of ``pending``, ``confirmed`` or ``rejected``.

            notes:
                Analyst notes associated with the decision.

            timestamp:
                Optional explicit UTC timestamp.

        Returns:
            ValidationResult describing the resulting state.

        Raises:
            TypeError:
                If finding is not a canonical Finding.

            ValueError:
                If status is invalid.
        """

        self._require_finding(
            finding
        )

        normalized_status = self._normalize_status(
            status
        )

        normalized_notes = self._normalize_notes(
            notes
        )

        validation_timestamp = (
            timestamp
            if timestamp is not None
            else datetime.now(
                timezone.utc
            )
        )

        if validation_timestamp.tzinfo is None:
            validation_timestamp = validation_timestamp.replace(
                tzinfo=timezone.utc
            )

        metadata = self._ensure_metadata(
            finding
        )

        self._record_history(
            metadata,
            status=normalized_status,
            notes=normalized_notes,
            timestamp=validation_timestamp,
        )

        metadata[
            VALIDATION_STATUS_KEY
        ] = normalized_status

        metadata[
            VALIDATED_MANUALLY_KEY
        ] = normalized_status != VALIDATION_PENDING

        metadata[
            VALIDATION_TIMESTAMP_KEY
        ] = validation_timestamp.isoformat()

        if normalized_notes:
            metadata[
                VALIDATION_NOTES_KEY
            ] = normalized_notes
        else:
            metadata.pop(
                VALIDATION_NOTES_KEY,
                None,
            )

        self._apply_state(
            finding,
            normalized_status,
        )

        return ValidationResult(
            finding_id=self._finding_id(
                finding
            ),
            status=normalized_status,
            confirmed=(
                normalized_status
                == VALIDATION_CONFIRMED
            ),
            confidence=str(
                finding.confidence
            ),
            finding_status=str(
                finding.status
            ),
            notes=normalized_notes,
            timestamp=validation_timestamp.isoformat(),
        )

    def confirm(
        self,
        finding: Finding,
        *,
        notes: str = "",
        timestamp: datetime | None = None,
    ) -> ValidationResult:
        """
        Explicitly confirm a Finding.
        """

        return self.validate(
            finding,
            status=VALIDATION_CONFIRMED,
            notes=notes,
            timestamp=timestamp,
        )

    def reject(
        self,
        finding: Finding,
        *,
        notes: str = "",
        timestamp: datetime | None = None,
    ) -> ValidationResult:
        """
        Explicitly reject a Finding.
        """

        return self.validate(
            finding,
            status=VALIDATION_REJECTED,
            notes=notes,
            timestamp=timestamp,
        )

    def mark_pending(
        self,
        finding: Finding,
        *,
        notes: str = "",
        timestamp: datetime | None = None,
    ) -> ValidationResult:
        """
        Return a Finding to pending validation state.
        """

        return self.validate(
            finding,
            status=VALIDATION_PENDING,
            notes=notes,
            timestamp=timestamp,
        )

    ###########################################################################
    # State Inspection
    ###########################################################################

    def status(
        self,
        finding: Finding,
    ) -> str:
        """
        Return the current validation status of a Finding.
        """

        self._require_finding(
            finding
        )

        metadata = getattr(
            finding,
            "metadata",
            {},
        )

        if isinstance(
            metadata,
            Mapping,
        ):
            value = metadata.get(
                VALIDATION_STATUS_KEY
            )

            if value is not None:
                try:
                    return self._normalize_status(
                        value
                    )
                except ValueError:
                    pass

        return VALIDATION_PENDING

    def is_confirmed(
        self,
        finding: Finding,
    ) -> bool:
        """
        Return True when a Finding is explicitly confirmed.
        """

        return (
            self.status(
                finding
            )
            == VALIDATION_CONFIRMED
        )

    def is_rejected(
        self,
        finding: Finding,
    ) -> bool:
        """
        Return True when a Finding is explicitly rejected.
        """

        return (
            self.status(
                finding
            )
            == VALIDATION_REJECTED
        )

    def is_pending(
        self,
        finding: Finding,
    ) -> bool:
        """
        Return True when a Finding remains pending validation.
        """

        return (
            self.status(
                finding
            )
            == VALIDATION_PENDING
        )

    def notes(
        self,
        finding: Finding,
    ) -> str:
        """
        Return the latest validation notes for a Finding.
        """

        self._require_finding(
            finding
        )

        metadata = getattr(
            finding,
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            return ""

        return str(
            metadata.get(
                VALIDATION_NOTES_KEY,
                "",
            )
            or ""
        )

    def history(
        self,
        finding: Finding,
    ) -> list[dict[str, Any]]:
        """
        Return a copy of the Finding's validation history.
        """

        self._require_finding(
            finding
        )

        metadata = getattr(
            finding,
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            return []

        history = metadata.get(
            VALIDATION_HISTORY_KEY,
            [],
        )

        if not isinstance(
            history,
            list,
        ):
            return []

        return deepcopy(
            history
        )

    ###########################################################################
    # Batch Operations
    ###########################################################################

    def validate_many(
        self,
        findings: Iterable[Finding],
        *,
        status: str,
        notes: str = "",
        timestamp: datetime | None = None,
    ) -> list[ValidationResult]:
        """
        Apply the same validation state to multiple Findings.

        Findings are processed in input order.
        """

        if findings is None:
            return []

        results: list[ValidationResult] = []

        for finding in findings:
            results.append(
                self.validate(
                    finding,
                    status=status,
                    notes=notes,
                    timestamp=timestamp,
                )
            )

        return results

    def summarize(
        self,
        findings: Iterable[Finding],
    ) -> ValidationSummary:
        """
        Produce aggregate validation statistics.
        """

        if findings is None:
            return ValidationSummary()

        summary = ValidationSummary()

        for finding in findings:
            self._require_finding(
                finding
            )

            summary.total += 1

            finding_id = self._finding_id(
                finding
            )

            if finding_id:
                summary.finding_ids.append(
                    finding_id
                )

            current_status = self.status(
                finding
            )

            if current_status == VALIDATION_PENDING:
                summary.pending += 1

            elif current_status == VALIDATION_CONFIRMED:
                summary.confirmed += 1

            elif current_status == VALIDATION_REJECTED:
                summary.rejected += 1

            else:
                summary.unknown += 1

        return summary

    ###########################################################################
    # Filtering
    ###########################################################################

    def filter_by_status(
        self,
        findings: Iterable[Finding],
        status: str,
    ) -> list[Finding]:
        """
        Return Findings currently having the requested validation status.
        """

        normalized_status = self._normalize_status(
            status
        )

        if findings is None:
            return []

        result: list[Finding] = []

        for finding in findings:
            self._require_finding(
                finding
            )

            if (
                self.status(
                    finding
                )
                == normalized_status
            ):
                result.append(
                    finding
                )

        return result

    def pending(
        self,
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Return Findings pending validation.
        """

        return self.filter_by_status(
            findings,
            VALIDATION_PENDING,
        )

    def confirmed(
        self,
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Return confirmed Findings.
        """

        return self.filter_by_status(
            findings,
            VALIDATION_CONFIRMED,
        )

    def rejected(
        self,
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Return rejected Findings.
        """

        return self.filter_by_status(
            findings,
            VALIDATION_REJECTED,
        )

    ###########################################################################
    # State Application
    ###########################################################################

    @staticmethod
    def _apply_state(
        finding: Finding,
        status: str,
    ) -> None:
        """
        Apply canonical confidence and lifecycle state.

        Severity is deliberately left unchanged.
        """

        if status == VALIDATION_CONFIRMED:
            finding.confidence = (
                Confidence.CONFIRMED.value
            )
            finding.status = "confirmed"

        elif status == VALIDATION_REJECTED:
            finding.confidence = (
                Confidence.LOW.value
            )
            finding.status = "rejected"

        else:
            finding.confidence = (
                Confidence.INFORMATIONAL.value
            )
            finding.status = "pending"

    ###########################################################################
    # Metadata Helpers
    ###########################################################################

    @staticmethod
    def _ensure_metadata(
        finding: Finding,
    ) -> dict[str, Any]:
        """
        Ensure Finding metadata is a mutable dictionary.
        """

        metadata = getattr(
            finding,
            "metadata",
            None,
        )

        if isinstance(
            metadata,
            dict,
        ):
            return metadata

        if metadata is None:
            finding.metadata = {}
        else:
            finding.metadata = dict(
                metadata
            )

        return finding.metadata

    @staticmethod
    def _record_history(
        metadata: dict[str, Any],
        *,
        status: str,
        notes: str,
        timestamp: datetime,
    ) -> None:
        """
        Append a validation decision to validation history.
        """

        history = metadata.get(
            VALIDATION_HISTORY_KEY
        )

        if not isinstance(
            history,
            list,
        ):
            history = []
            metadata[
                VALIDATION_HISTORY_KEY
            ] = history

        history.append(
            {
                "status": status,
                "notes": notes,
                "timestamp": timestamp.isoformat(),
            }
        )

    ###########################################################################
    # Normalization
    ###########################################################################

    @staticmethod
    def _normalize_status(
        value: Any,
    ) -> str:
        """
        Normalize a validation status.
        """

        normalized = str(
            value
        ).strip().lower()

        aliases = {
            "pending": VALIDATION_PENDING,
            "unvalidated": VALIDATION_PENDING,
            "unknown": VALIDATION_PENDING,
            "confirmed": VALIDATION_CONFIRMED,
            "confirm": VALIDATION_CONFIRMED,
            "valid": VALIDATION_CONFIRMED,
            "rejected": VALIDATION_REJECTED,
            "reject": VALIDATION_REJECTED,
            "invalid": VALIDATION_REJECTED,
        }

        normalized = aliases.get(
            normalized,
            normalized,
        )

        valid = {
            VALIDATION_PENDING,
            VALIDATION_CONFIRMED,
            VALIDATION_REJECTED,
        }

        if normalized not in valid:
            raise ValueError(
                "Invalid validation status: "
                f"{value!r}. Expected one of: "
                f"{', '.join(sorted(valid))}."
            )

        return normalized

    @staticmethod
    def _normalize_notes(
        notes: Any,
    ) -> str:
        """
        Normalize analyst validation notes.
        """

        if notes is None:
            return ""

        return str(
            notes
        ).strip()

    ###########################################################################
    # Validation Helpers
    ###########################################################################

    @staticmethod
    def _require_finding(
        finding: Finding,
    ) -> None:
        """
        Ensure an operation receives the canonical Finding type.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "Finding validation requires a canonical "
                "scopeforgex.models.finding.Finding object."
            )

    @staticmethod
    def _finding_id(
        finding: Finding,
    ) -> str:
        """
        Return a Finding identifier.
        """

        return str(
            getattr(
                finding,
                "finding_id",
                "",
            )
            or ""
        ).strip()


###############################################################################
# Convenience API
###############################################################################


def validate_finding(
    finding: Finding,
    *,
    status: str = VALIDATION_CONFIRMED,
    notes: str = "",
    timestamp: datetime | None = None,
) -> ValidationResult:
    """
    Validate one Finding using a temporary FindingValidator.
    """

    return FindingValidator().validate(
        finding,
        status=status,
        notes=notes,
        timestamp=timestamp,
    )


def confirm_finding(
    finding: Finding,
    *,
    notes: str = "",
    timestamp: datetime | None = None,
) -> ValidationResult:
    """
    Confirm one Finding using a temporary FindingValidator.
    """

    return FindingValidator().confirm(
        finding,
        notes=notes,
        timestamp=timestamp,
    )


def reject_finding(
    finding: Finding,
    *,
    notes: str = "",
    timestamp: datetime | None = None,
) -> ValidationResult:
    """
    Reject one Finding using a temporary FindingValidator.
    """

    return FindingValidator().reject(
        finding,
        notes=notes,
        timestamp=timestamp,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    # Constants.
    "VALIDATION_PENDING",
    "VALIDATION_CONFIRMED",
    "VALIDATION_REJECTED",
    "VALIDATION_STATUS_KEY",
    "VALIDATED_MANUALLY_KEY",
    "VALIDATION_TIMESTAMP_KEY",
    "VALIDATION_NOTES_KEY",
    "VALIDATION_HISTORY_KEY",

    # Data models.
    "ValidationResult",
    "ValidationSummary",

    # Validator.
    "FindingValidator",

    # Convenience API.
    "validate_finding",
    "confirm_finding",
    "reject_finding",
]
