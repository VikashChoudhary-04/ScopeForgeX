"""
ScopeForgeX Manual Findings
============================

Manual assessment support for the universal ScopeForgeX Finding model.

Manual findings allow a security professional to add analyst-generated
observations to the same finding pipeline used by automated collectors,
native analyzers and specialized validation tools.

Manual assessment capabilities
-------------------------------

- Manual finding creation
- Manual evidence attachment
- Manual validation
- Impact assessment
- Analyst notes
- Finding status updates
- Finding serialization

Manual findings use the canonical Finding model. They are not a separate
finding type and do not bypass normalization, confidence, risk, correlation,
deduplication or reporting.

Example
-------

    manual = ManualFindingManager()

    finding = manual.create(
        title="Broken Access Control",
        category="access_control",
        severity="High",
        target="https://example.com",
        url="https://example.com/admin",
        description="A low-privileged user can access an administrative endpoint.",
        evidence={
            "request": "GET /admin HTTP/1.1",
            "response": "HTTP/1.1 200 OK",
        },
        impact="Unauthorized access to administrative functionality.",
        remediation="Enforce server-side authorization checks.",
    )

    manual.validate(
        finding,
        confirmed=True,
        notes="Reproduced using a low-privileged test account.",
    )

Design Principles
-----------------

- Manual findings use the universal Finding model.
- Manual findings remain traceable as analyst-generated observations.
- Manual findings never execute external tools.
- Manual findings never perform network requests.
- Manual evidence is preserved on the Finding.
- Validation changes confidence/status explicitly.
- Creating a manual finding does not automatically mark it as confirmed.
- Analyst notes remain separate from the primary finding description.
- Manual severity does not imply manual confirmation.
- IDs are deterministic within a manager instance.
- Existing Finding objects can be updated without being replaced.
- The module remains independent from reporting.

v1.3.0
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from scopeforgex.models.finding import (
    DEFAULT_CATEGORY,
    DEFAULT_CONFIDENCE,
    DEFAULT_SEVERITY,
    DEFAULT_STATUS,
    Finding,
)
from scopeforgex.runtime.enums import Confidence, Severity


###############################################################################
# Constants
###############################################################################


MANUAL_SOURCE_TOOL = "ScopeForgeX Manual Assessment"

MANUAL_DETECTION_METHOD = "Manual Analyst Assessment"

MANUAL_FINDING_PREFIX = "SF-MANUAL-"

MANUAL_CATEGORY = "manual_assessment"

VALIDATION_PENDING = "pending"
VALIDATION_CONFIRMED = "confirmed"
VALIDATION_REJECTED = "rejected"


###############################################################################
# Normalization Helpers
###############################################################################


def _text(
    value: Any,
) -> str:
    """
    Normalize a value into stripped text.
    """

    if value is None:
        return ""

    return str(
        value
    ).strip()


def _optional_text(
    value: Any,
) -> str | None:
    """
    Normalize an optional textual value.
    """

    value = _text(
        value
    )

    return value or None


def _severity(
    value: Any,
) -> str:
    """
    Normalize a manual finding severity.

    Unknown values fall back to the canonical informational severity rather
    than allowing a non-canonical value into the Finding model.
    """

    if isinstance(
        value,
        Severity,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    aliases = {
        "informational": Severity.INFO.value,
        "information": Severity.INFO.value,
        "info": Severity.INFO.value,
        "moderate": Severity.MEDIUM.value,
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    valid = {
        severity.value
        for severity in Severity
    }

    if normalized not in valid:
        return DEFAULT_SEVERITY

    return normalized


def _confidence(
    value: Any,
) -> str:
    """
    Normalize a manual finding confidence.
    """

    if isinstance(
        value,
        Confidence,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    aliases = {
        "info": Confidence.INFORMATIONAL.value,
        "information": Confidence.INFORMATIONAL.value,
        "informational": Confidence.INFORMATIONAL.value,
    }

    normalized = aliases.get(
        normalized,
        normalized,
    )

    valid = {
        confidence.value
        for confidence in Confidence
    }

    if normalized not in valid:
        return DEFAULT_CONFIDENCE

    return normalized


def _references(
    value: Any,
) -> list[str]:
    """
    Normalize references into a unique ordered list.
    """

    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        value = value.strip()

        return (
            [value]
            if value
            else []
        )

    if isinstance(
        value,
        Iterable,
    ):
        result: list[str] = []

        for item in value:
            item = _text(
                item
            )

            if (
                item
                and item not in result
            ):
                result.append(
                    item
                )

        return result

    value = _text(
        value
    )

    return (
        [value]
        if value
        else []
    )


def _evidence(
    value: Any,
) -> Any:
    """
    Normalize manual evidence without destroying its original structure.

    Mapping and collection values are copied so callers cannot accidentally
    mutate the Finding through their original object after creation.
    """

    if value is None:
        return None

    if isinstance(
        value,
        Mapping,
    ):
        return deepcopy(
            dict(
                value
            )
        )

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return deepcopy(
            list(
                value
            )
        )

    return value


###############################################################################
# Manual Finding Manager
###############################################################################


class ManualFindingManager:
    """
    Create and manage analyst-generated ScopeForgeX findings.

    The manager is intentionally lightweight. It does not maintain a separate
    persistence layer and does not replace the canonical Finding model.

    Findings created by this manager can be passed directly into:

        correlation
        deduplication
        confidence processing
        risk classification
        evidence management
        reporting
    """

    name = "manual_finding_manager"

    description = (
        "Create and manage analyst-generated ScopeForgeX findings using "
        "the canonical Finding model."
    )

    def __init__(
        self,
        *,
        id_prefix: str = MANUAL_FINDING_PREFIX,
        starting_number: int = 1,
    ) -> None:
        """
        Initialize a manual finding manager.

        Args:
            id_prefix:
                Prefix used for generated manual finding identifiers.

            starting_number:
                First numeric identifier to allocate.

        Raises:
            ValueError:
                If starting_number is less than one.
        """

        if starting_number < 1:
            raise ValueError(
                "starting_number must be greater than or equal to 1."
            )

        self.id_prefix = _text(
            id_prefix
        )

        if not self.id_prefix:
            raise ValueError(
                "id_prefix cannot be empty."
            )

        self._next_number = starting_number

    ###########################################################################
    # Identifier Management
    ###########################################################################

    def next_id(
        self,
    ) -> str:
        """
        Allocate the next manual finding identifier.

        Example:
            SF-MANUAL-001
            SF-MANUAL-002
            SF-MANUAL-003
        """

        finding_id = (
            f"{self.id_prefix}"
            f"{self._next_number:03d}"
        )

        self._next_number += 1

        return finding_id

    ###########################################################################
    # Finding Creation
    ###########################################################################

    def create(
        self,
        *,
        title: str,
        description: str = "",
        category: str = MANUAL_CATEGORY,
        severity: Any = DEFAULT_SEVERITY,
        confidence: Any = DEFAULT_CONFIDENCE,
        target: str = "",
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        parameter: str | None = None,
        evidence: Any = None,
        impact: str = "",
        remediation: str = "",
        references: Any = None,
        status: str = DEFAULT_STATUS,
        analyst_notes: str = "",
        validation_status: str = VALIDATION_PENDING,
        finding_id: str | None = None,
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Finding:
        """
        Create a canonical manual Finding.

        A newly created manual finding is not automatically confirmed.

        Args:
            title:
                Human-readable finding title.

            description:
                Technical description of the observation.

            category:
                Canonical finding category.

            severity:
                Finding severity.

            confidence:
                Detection confidence.

            target:
                Assessment target.

            host:
                Affected host.

            port:
                Affected network port.

            url:
                Affected URL or endpoint.

            parameter:
                Affected parameter.

            evidence:
                Analyst-provided technical evidence.

            impact:
                Security or business impact.

            remediation:
                Recommended remediation.

            references:
                CWE, CVE, documentation or other references.

            status:
                Finding lifecycle status.

            analyst_notes:
                Internal analyst notes.

            validation_status:
                Manual validation state.

            finding_id:
                Optional explicit finding identifier. When omitted, an
                SF-MANUAL-NNN identifier is generated.

            timestamp:
                Finding creation/observation timestamp.

            metadata:
                Additional structured metadata.

        Returns:
            A canonical ScopeForgeX Finding object.

        Raises:
            ValueError:
                If required finding information is missing or validation state
                is invalid.
        """

        title = _text(
            title
        )

        if not title:
            raise ValueError(
                "Manual finding title cannot be empty."
            )

        category = (
            _text(
                category
            )
            or MANUAL_CATEGORY
        )

        target = _text(
            target
        )

        description = _text(
            description
        )

        analyst_notes = _text(
            analyst_notes
        )

        validation_status = self._normalize_validation_status(
            validation_status
        )

        finding_id = (
            _text(
                finding_id
            )
            or self.next_id()
        )

        finding_metadata: dict[str, Any] = {}

        if metadata is not None:
            finding_metadata.update(
                deepcopy(
                    dict(
                        metadata
                    )
                )
            )

        finding_metadata.update(
            self._manual_metadata(
                analyst_notes=analyst_notes,
                validation_status=validation_status,
            )
        )

        return Finding(
            finding_id=finding_id,
            title=title,
            category=category,
            severity=_severity(
                severity
            ),
            confidence=_confidence(
                confidence
            ),
            target=target,
            host=_optional_text(
                host
            ),
            port=port,
            url=_optional_text(
                url
            ),
            parameter=_optional_text(
                parameter
            ),
            description=description,
            evidence=_evidence(
                evidence
            ),
            source_tool=MANUAL_SOURCE_TOOL,
            detection_method=MANUAL_DETECTION_METHOD,
            timestamp=(
                timestamp
                if timestamp is not None
                else datetime.now(
                    timezone.utc
                )
            ),
            references=_references(
                references
            ),
            impact=_text(
                impact
            ),
            remediation=_text(
                remediation
            ),
            status=_text(
                status
            ) or DEFAULT_STATUS,
            metadata=finding_metadata,
        )

    ###########################################################################
    # Manual Evidence
    ###########################################################################

    def add_evidence(
        self,
        finding: Finding,
        evidence: Any,
    ) -> Finding:
        """
        Attach or update manual evidence on an existing Finding.

        The Finding object is updated in place and returned for convenient
        chaining.

        Existing evidence is preserved when both the existing evidence and
        new evidence are mappings. New keys overwrite matching keys because
        the latest analyst input is authoritative for that evidence field.
        """

        self._require_finding(
            finding
        )

        if evidence is None:
            return finding

        normalized = _evidence(
            evidence
        )

        if (
            isinstance(
                finding.evidence,
                Mapping,
            )
            and isinstance(
                normalized,
                Mapping,
            )
        ):
            merged = deepcopy(
                dict(
                    finding.evidence
                )
            )

            merged.update(
                deepcopy(
                    dict(
                        normalized
                    )
                )
            )

            finding.evidence = merged

        elif finding.evidence is None:
            finding.evidence = normalized

        else:
            finding.evidence = [
                finding.evidence,
                normalized,
            ]

        return finding

    ###########################################################################
    # Analyst Notes
    ###########################################################################

    def add_notes(
        self,
        finding: Finding,
        notes: str,
    ) -> Finding:
        """
        Add analyst notes to an existing manual finding.

        Multiple note additions are preserved in chronological insertion
        order. Existing notes are not silently discarded.
        """

        self._require_finding(
            finding
        )

        notes = _text(
            notes
        )

        if not notes:
            return finding

        metadata = self._ensure_metadata(
            finding
        )

        existing = metadata.get(
            "analyst_notes",
        )

        if not existing:
            metadata[
                "analyst_notes"
            ] = notes

        else:
            metadata[
                "analyst_notes"
            ] = (
                f"{existing}\n"
                f"{notes}"
            )

        return finding

    ###########################################################################
    # Impact Assessment
    ###########################################################################

    def set_impact(
        self,
        finding: Finding,
        impact: str,
    ) -> Finding:
        """
        Set or update the impact assessment for a manual finding.
        """

        self._require_finding(
            finding
        )

        finding.impact = _text(
            impact
        )

        return finding

    ###########################################################################
    # Remediation
    ###########################################################################

    def set_remediation(
        self,
        finding: Finding,
        remediation: str,
    ) -> Finding:
        """
        Set or update remediation guidance for a manual finding.
        """

        self._require_finding(
            finding
        )

        finding.remediation = _text(
            remediation
        )

        return finding

    ###########################################################################
    # Validation
    ###########################################################################

    def validate(
        self,
        finding: Finding,
        *,
        confirmed: bool = True,
        notes: str = "",
    ) -> Finding:
        """
        Record manual validation of a Finding.

        When confirmed=True:

            validation_status = confirmed
            confidence = Confirmed
            status = confirmed

        When confirmed=False:

            validation_status = rejected
            confidence = Low
            status = rejected

        This method deliberately requires an explicit decision. Creating a
        manual finding alone never establishes confirmation.
        """

        self._require_finding(
            finding
        )

        notes = _text(
            notes
        )

        metadata = self._ensure_metadata(
            finding
        )

        if confirmed:
            finding.confidence = (
                Confidence.CONFIRMED.value
            )

            finding.status = "confirmed"

            metadata[
                "validation_status"
            ] = VALIDATION_CONFIRMED

        else:
            finding.confidence = (
                Confidence.LOW.value
            )

            finding.status = "rejected"

            metadata[
                "validation_status"
            ] = VALIDATION_REJECTED

        metadata[
            "validated_manually"
        ] = True

        metadata[
            "validation_timestamp"
        ] = datetime.now(
            timezone.utc
        ).isoformat()

        if notes:
            self.add_notes(
                finding,
                notes,
            )

        return finding

    def mark_pending(
        self,
        finding: Finding,
        *,
        notes: str = "",
    ) -> Finding:
        """
        Return a finding to pending validation state.
        """

        self._require_finding(
            finding
        )

        finding.confidence = (
            Confidence.INFORMATIONAL.value
        )

        finding.status = "pending"

        metadata = self._ensure_metadata(
            finding
        )

        metadata[
            "validation_status"
        ] = VALIDATION_PENDING

        metadata[
            "validated_manually"
        ] = False

        metadata.pop(
            "validation_timestamp",
            None,
        )

        if notes:
            self.add_notes(
                finding,
                notes,
            )

        return finding

    ###########################################################################
    # Finding Updates
    ###########################################################################

    def update(
        self,
        finding: Finding,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: Any | None = None,
        confidence: Any | None = None,
        target: str | None = None,
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        parameter: str | None = None,
        impact: str | None = None,
        remediation: str | None = None,
        references: Any | None = None,
        status: str | None = None,
        analyst_notes: str | None = None,
        validation_status: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Finding:
        """
        Update mutable fields on an existing manual Finding.

        The object remains the same Finding instance so references held by
        correlation, evidence or workflow code remain valid.
        """

        self._require_finding(
            finding
        )

        if title is not None:
            title = _text(
                title
            )

            if not title:
                raise ValueError(
                    "Manual finding title cannot be empty."
                )

            finding.title = title

        if description is not None:
            finding.description = _text(
                description
            )

        if severity is not None:
            finding.severity = _severity(
                severity
            )

        if confidence is not None:
            finding.confidence = _confidence(
                confidence
            )

        if target is not None:
            finding.target = _text(
                target
            )

        if host is not None:
            finding.host = _optional_text(
                host
            )

        if port is not None:
            finding.port = port

        if url is not None:
            finding.url = _optional_text(
                url
            )

        if parameter is not None:
            finding.parameter = _optional_text(
                parameter
            )

        if impact is not None:
            finding.impact = _text(
                impact
            )

        if remediation is not None:
            finding.remediation = _text(
                remediation
            )

        if references is not None:
            finding.references = _references(
                references
            )

        if status is not None:
            finding.status = _text(
                status
            )

        if analyst_notes is not None:
            self._ensure_metadata(
                finding
            )[
                "analyst_notes"
            ] = _text(
                analyst_notes
            )

        if validation_status is not None:
            normalized_validation = (
                self._normalize_validation_status(
                    validation_status
                )
            )

            self._ensure_metadata(
                finding
            )[
                "validation_status"
            ] = normalized_validation

        if metadata is not None:
            self._ensure_metadata(
                finding
            ).update(
                deepcopy(
                    dict(
                        metadata
                    )
                )
            )

        return finding

    ###########################################################################
    # Serialization
    ###########################################################################

    @staticmethod
    def serialize(
        finding: Finding,
    ) -> dict[str, Any]:
        """
        Serialize a manual Finding.

        The canonical Finding serialization is used when available.
        Manual metadata remains embedded in the Finding metadata.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "serialize() expects a canonical Finding object."
            )

        if hasattr(
            finding,
            "as_dict",
        ):
            return finding.as_dict()

        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "target": finding.target,
            "host": finding.host,
            "port": finding.port,
            "url": finding.url,
            "parameter": finding.parameter,
            "description": finding.description,
            "evidence": finding.evidence,
            "source_tool": finding.source_tool,
            "detection_method": finding.detection_method,
            "timestamp": finding.timestamp.isoformat(),
            "cwe": finding.cwe,
            "cve": finding.cve,
            "references": list(
                finding.references
            ),
            "impact": finding.impact,
            "remediation": finding.remediation,
            "status": finding.status,
            "metadata": dict(
                finding.metadata
            ),
        }

    ###########################################################################
    # Batch Operations
    ###########################################################################

    def create_many(
        self,
        findings: Iterable[Mapping[str, Any]],
    ) -> list[Finding]:
        """
        Create multiple manual findings.

        Each mapping is passed to create(). Generated identifiers remain
        deterministic in input order.
        """

        if findings is None:
            return []

        result: list[Finding] = []

        for specification in findings:
            if not isinstance(
                specification,
                Mapping,
            ):
                raise TypeError(
                    "create_many() expects mappings containing finding fields."
                )

            result.append(
                self.create(
                    **dict(
                        specification
                    )
                )
            )

        return result

    ###########################################################################
    # Validation Helpers
    ###########################################################################

    @staticmethod
    def _normalize_validation_status(
        value: Any,
    ) -> str:
        """
        Normalize a manual validation status.
        """

        normalized = _text(
            value
        ).lower()

        aliases = {
            "pending": VALIDATION_PENDING,
            "unvalidated": VALIDATION_PENDING,
            "confirmed": VALIDATION_CONFIRMED,
            "valid": VALIDATION_CONFIRMED,
            "rejected": VALIDATION_REJECTED,
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
                "Invalid manual validation status: "
                f"{value!r}. Expected one of: "
                f"{', '.join(sorted(valid))}."
            )

        return normalized

    @staticmethod
    def _manual_metadata(
        *,
        analyst_notes: str,
        validation_status: str,
    ) -> dict[str, Any]:
        """
        Build metadata specific to manual assessment.
        """

        metadata: dict[str, Any] = {
            "manual_finding": True,
            "manual_assessment": True,
            "validation_status": validation_status,
            "validated_manually": (
                validation_status
                == VALIDATION_CONFIRMED
            ),
        }

        if analyst_notes:
            metadata[
                "analyst_notes"
            ] = analyst_notes

        return metadata

    @staticmethod
    def _ensure_metadata(
        finding: Finding,
    ) -> dict[str, Any]:
        """
        Ensure a Finding has a mutable metadata dictionary.
        """

        if not isinstance(
            finding.metadata,
            dict,
        ):
            finding.metadata = dict(
                finding.metadata
            )

        return finding.metadata

    @staticmethod
    def _require_finding(
        finding: Finding,
    ) -> None:
        """
        Validate that a supplied object is the canonical Finding type.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "Manual finding operations require a canonical "
                "scopeforgex.models.finding.Finding object."
            )


###############################################################################
# Convenience API
###############################################################################


def create_manual_finding(
    *,
    title: str,
    description: str = "",
    category: str = MANUAL_CATEGORY,
    severity: Any = DEFAULT_SEVERITY,
    confidence: Any = DEFAULT_CONFIDENCE,
    target: str = "",
    host: str | None = None,
    port: int | None = None,
    url: str | None = None,
    parameter: str | None = None,
    evidence: Any = None,
    impact: str = "",
    remediation: str = "",
    references: Any = None,
    status: str = DEFAULT_STATUS,
    analyst_notes: str = "",
    validation_status: str = VALIDATION_PENDING,
    finding_id: str | None = None,
    timestamp: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
    manager: ManualFindingManager | None = None,
) -> Finding:
    """
    Convenience function for creating one manual finding.

    A supplied manager is reused so generated identifiers continue from its
    current sequence. When no manager is supplied, a temporary manager is
    created and the first identifier is therefore SF-MANUAL-001.
    """

    manager = (
        manager
        if manager is not None
        else ManualFindingManager()
    )

    return manager.create(
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        target=target,
        host=host,
        port=port,
        url=url,
        parameter=parameter,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        references=references,
        status=status,
        analyst_notes=analyst_notes,
        validation_status=validation_status,
        finding_id=finding_id,
        timestamp=timestamp,
        metadata=metadata,
    )


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "MANUAL_SOURCE_TOOL",
    "MANUAL_DETECTION_METHOD",
    "MANUAL_FINDING_PREFIX",
    "MANUAL_CATEGORY",
    "VALIDATION_PENDING",
    "VALIDATION_CONFIRMED",
    "VALIDATION_REJECTED",
    "ManualFindingManager",
    "create_manual_finding",
]
