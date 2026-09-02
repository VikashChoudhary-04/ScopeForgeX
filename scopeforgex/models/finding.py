"""
ScopeForgeX Universal Finding Model
===================================

Canonical finding representation for the ScopeForgeX assessment pipeline.

Architecture
------------

Tool Output / Native Analyzer
            |
            v
       Observation
            |
            v
    FindingNormalizer
            |
            v
         Finding
            |
      +------+------+
      |             |
      v             v
Correlation    Deduplication
      |             |
      +------+------+
             |
             v
      Risk / Confidence
             |
             v
        Evidence Store
             |
             v
        Report Generator

Design Principles
-----------------

- Finding is the universal normalized assessment record.
- Tool-specific parsing belongs to collectors, not this model.
- Native analyzer logic belongs to analyzers, not this model.
- Detection does not automatically mean confirmed exploitation.
- Confidence is independent from severity.
- Evidence is preserved as structured data.
- Optional fields remain optional rather than being populated with guesses.
- The model contains no execution or network logic.
- Semantic identity is deterministic and independent of volatile provenance.
- Explicit finding IDs are preserved.
- Missing finding IDs receive deterministic ScopeForgeX identifiers.

v1.3.0
"""

from __future__ import annotations

import hashlib
import json

from dataclasses import (
    asdict,
    dataclass,
    field,
)

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Mapping,
)


###############################################################################
# Constants
###############################################################################


DEFAULT_CATEGORY = "security_issue"

DEFAULT_SEVERITY = "Informational"

DEFAULT_CONFIDENCE = "Informational"

DEFAULT_STATUS = "Open"

FINDING_STATUS_PENDING = "Pending"

FINDING_STATUS_CONFIRMED = "Confirmed"


VALID_SEVERITIES = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
)


VALID_CONFIDENCES = (
    "Confirmed",
    "High",
    "Medium",
    "Low",
    "Informational",
)


VALID_STATUSES = (
    "Open",
    "Confirmed",
    "False Positive",
    "Accepted Risk",
    "Remediated",
    "Closed",
    "Pending",
)


###############################################################################
# Utility Functions
###############################################################################


def utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


def _text(
    value: Any,
) -> str:
    """
    Return a normalized string representation.
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
    Return normalized text or None when empty.
    """

    normalized = _text(
        value
    )

    return normalized or None


def _normalize_identity_text(
    value: Any,
) -> str:
    """
    Normalize text used for semantic identity.
    """

    normalized = _text(
        value
    )

    return " ".join(
        normalized.lower().split()
    )


def _normalize_severity(
    value: Any,
) -> str:
    """
    Normalize a severity value.

    Unknown or missing values become Informational.
    """

    normalized = _text(
        value
    )

    if not normalized:
        return DEFAULT_SEVERITY

    lookup = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Informational",
        "information": "Informational",
        "informational": "Informational",
    }

    return lookup.get(
        normalized.lower(),
        DEFAULT_SEVERITY,
    )


def _normalize_confidence(
    value: Any,
) -> str:
    """
    Normalize a confidence value.
    """

    normalized = _text(
        value
    )

    if not normalized:
        return DEFAULT_CONFIDENCE

    lookup = {
        "confirmed": "Confirmed",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
        "information": "Informational",
        "informational": "Informational",
    }

    return lookup.get(
        normalized.lower(),
        DEFAULT_CONFIDENCE,
    )


def _normalize_status(
    value: Any,
) -> str:
    """
    Normalize a finding lifecycle status.
    """

    normalized = _text(
        value
    )

    if not normalized:
        return DEFAULT_STATUS

    lookup = {
        "open": "Open",
        "confirmed": "Confirmed",
        "false positive": "False Positive",
        "false_positive": "False Positive",
        "accepted risk": "Accepted Risk",
        "accepted_risk": "Accepted Risk",
        "remediated": "Remediated",
        "closed": "Closed",
        "pending": "Pending",
    }

    return lookup.get(
        normalized.lower(),
        DEFAULT_STATUS,
    )


def _normalize_port(
    value: Any,
) -> int | None:
    """
    Normalize a network port.
    """

    if value is None or value == "":
        return None

    try:
        port = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if 0 <= port <= 65535:
        return port

    return None


def _normalize_references(
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
        value = [
            value
        ]

    try:
        iterator = iter(
            value
        )
    except TypeError:
        value = [
            value
        ]

        iterator = iter(
            value
        )

    references: list[str] = []

    seen: set[str] = set()

    for item in iterator:

        reference = _text(
            item
        )

        if not reference or reference in seen:
            continue

        seen.add(
            reference
        )

        references.append(
            reference
        )

    return references


def _normalize_evidence(
    value: Any,
) -> Any:
    """
    Normalize evidence while preserving its structure.
    """

    if value is None:
        return ""

    if isinstance(
        value,
        Mapping,
    ):
        return dict(
            value
        )

    if isinstance(
        value,
        list,
    ):
        return list(
            value
        )

    if isinstance(
        value,
        tuple,
    ):
        return list(
            value
        )

    return value


def _normalize_timestamp(
    value: Any,
) -> datetime:
    """
    Normalize a timestamp to an aware UTC datetime.
    """

    if isinstance(
        value,
        datetime,
    ):

        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value.astimezone(
            timezone.utc
        )

    if isinstance(
        value,
        str,
    ):

        text = value.strip()

        if text:

            try:

                parsed = datetime.fromisoformat(
                    text.replace(
                        "Z",
                        "+00:00",
                    )
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed.astimezone(
                    timezone.utc
                )

            except ValueError:
                pass

    return utc_now()


###############################################################################
# Evidence Compatibility Object
###############################################################################


class FindingEvidence:
    """
    Flexible structured evidence container.

    Collector-specific evidence can remain structured without forcing
    tool-specific fields into the universal Finding schema.
    """

    def __init__(
        self,
        **values: Any,
    ) -> None:

        self._values = dict(
            values
        )

        for key, value in self._values.items():
            setattr(
                self,
                key,
                value,
            )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the evidence container.
        """

        return dict(
            self._values
        )

    def to_dict(
        self,
    ) -> dict[str, Any]:
        """
        Compatibility alias for as_dict().
        """

        return self.as_dict()


###############################################################################
# Universal Finding
###############################################################################


@dataclass(slots=True)
class Finding:
    """
    Universal normalized ScopeForgeX finding.

    The model is the canonical representation consumed by normalization,
    deduplication, correlation, risk classification, evidence handling,
    aggregation, and reporting.
    """

    id: str

    title: str

    category: str

    severity: str = DEFAULT_SEVERITY

    confidence: str = DEFAULT_CONFIDENCE

    target: str = ""

    host: str | None = None

    port: int | None = None

    url: str | None = None

    parameter: str | None = None

    description: str = ""

    evidence: Any = ""

    source_tool: str = ""

    detection_method: str = ""

    timestamp: datetime = field(
        default_factory=utc_now
    )

    cwe: str | None = None

    cve: str | None = None

    references: list[str] = field(
        default_factory=list
    )

    impact: str = ""

    remediation: str = ""

    status: str = DEFAULT_STATUS

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    ###########################################################################
    # Finding ID Compatibility
    ###########################################################################

    @property
    def finding_id(
        self,
    ) -> str:
        """
        Return the canonical finding identifier.

        ``finding_id`` is the public compatibility name used throughout the
        findings subsystem while ``id`` remains the underlying model field.
        """

        return self.id

    @finding_id.setter
    def finding_id(
        self,
        value: Any,
    ) -> None:
        """
        Update the finding identifier.
        """

        self.id = _text(
            value
        )

    ###########################################################################
    # Severity / Confidence / Status Compatibility
    ###########################################################################

    @property
    def severity_level(
        self,
    ) -> str:
        """
        Return the canonical severity value.

        Compatibility alias used by risk and deduplication components.
        """

        return self.severity

    @severity_level.setter
    def severity_level(
        self,
        value: Any,
    ) -> None:
        """
        Update the canonical severity value.
        """

        self.severity = _normalize_severity(
            value
        )

    @property
    def confidence_level(
        self,
    ) -> str:
        """
        Return the canonical confidence value.

        Compatibility alias used by findings processing components.
        """

        return self.confidence

    @confidence_level.setter
    def confidence_level(
        self,
        value: Any,
    ) -> None:
        """
        Update the canonical confidence value.
        """

        self.confidence = _normalize_confidence(
            value
        )

    @property
    def finding_status(
        self,
    ) -> str:
        """
        Return the canonical finding lifecycle status.
        """

        return self.status

    @finding_status.setter
    def finding_status(
        self,
        value: Any,
    ) -> None:
        """
        Update the canonical finding lifecycle status.
        """

        self.status = _normalize_status(
            value
        )

    ###########################################################################
    # Initialization
    ###########################################################################

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize externally supplied values.
        """

        self.id = _text(
            self.id
        )

        self.title = _text(
            self.title
        )

        self.category = _text(
            self.category
        )

        if not self.category:
            self.category = DEFAULT_CATEGORY

        self.severity = _normalize_severity(
            self.severity
        )

        self.confidence = _normalize_confidence(
            self.confidence
        )

        self.target = _text(
            self.target
        )

        self.host = _optional_text(
            self.host
        )

        self.port = _normalize_port(
            self.port
        )

        self.url = _optional_text(
            self.url
        )

        self.parameter = _optional_text(
            self.parameter
        )

        self.description = _text(
            self.description
        )

        self.evidence = _normalize_evidence(
            self.evidence
        )

        self.source_tool = _text(
            self.source_tool
        )

        self.detection_method = _text(
            self.detection_method
        )

        self.timestamp = _normalize_timestamp(
            self.timestamp
        )

        self.cwe = _optional_text(
            self.cwe
        )

        self.cve = _optional_text(
            self.cve
        )

        self.references = _normalize_references(
            self.references
        )

        self.impact = _text(
            self.impact
        )

        self.remediation = _text(
            self.remediation
        )

        self.status = _normalize_status(
            self.status
        )

        if not isinstance(
            self.metadata,
            dict,
        ):
            self.metadata = dict(
                self.metadata
            )

    ###########################################################################
    # Factory
    ###########################################################################

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        finding_id: str | None = None,
    ) -> "Finding":
        """
        Construct a canonical Finding from a mapping.

        Explicit identifiers are preserved. When an observation does not
        contain an identifier, a deterministic ScopeForgeX identifier is
        generated from semantic finding attributes.
        """

        if not isinstance(
            data,
            Mapping,
        ):
            raise TypeError(
                "Finding data must be a mapping."
            )

        category = (
            data.get(
                "category"
            )
            or data.get(
                "finding_type"
            )
            or data.get(
                "observation_type"
            )
            or DEFAULT_CATEGORY
        )

        title = _text(
            data.get(
                "title"
            )
        )

        if not title:
            title = _text(
                data.get(
                    "value"
                )
            )

        if not title:
            title = "Untitled Finding"

        resolved_id = (
            _text(
                finding_id
            )
            or _text(
                data.get(
                    "finding_id"
                )
            )
            or _text(
                data.get(
                    "id"
                )
            )
        )

        if not resolved_id:

            semantic_payload = {
                "category": _normalize_identity_text(
                    category
                ),

                "title": _normalize_identity_text(
                    title
                ),

                "target": _normalize_identity_text(
                    data.get(
                        "target",
                        "",
                    )
                ),

                "host": _normalize_identity_text(
                    data.get(
                        "host",
                        "",
                    )
                ),

                "port": _normalize_port(
                    data.get(
                        "port"
                    )
                ),

                "url": _normalize_identity_text(
                    data.get(
                        "url",
                        "",
                    )
                ),

                "parameter": _normalize_identity_text(
                    data.get(
                        "parameter",
                        "",
                    )
                ),
            }

            payload = json.dumps(
                semantic_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(
                    ",",
                    ":",
                ),
            )

            digest = hashlib.sha256(
                payload.encode(
                    "utf-8"
                )
            ).hexdigest()

            resolved_id = (
                "SF-"
                + digest[:16].upper()
            )

        return cls(
            id=resolved_id,

            title=title,

            category=_text(
                category
            ),

            severity=data.get(
                "severity",
                data.get(
                    "severity_level",
                    DEFAULT_SEVERITY,
                ),
            ),

            confidence=data.get(
                "confidence",
                data.get(
                    "confidence_level",
                    DEFAULT_CONFIDENCE,
                ),
            ),

            target=data.get(
                "target",
                "",
            ),

            host=data.get(
                "host"
            ),

            port=data.get(
                "port"
            ),

            url=data.get(
                "url"
            ),

            parameter=data.get(
                "parameter"
            ),

            description=data.get(
                "description",
                "",
            ),

            evidence=data.get(
                "evidence",
                "",
            ),

            source_tool=data.get(
                "source_tool",
                data.get(
                    "source",
                    data.get(
                        "tool",
                        "",
                    ),
                ),
            ),

            detection_method=data.get(
                "detection_method",
                "",
            ),

            timestamp=data.get(
                "timestamp"
            ),

            cwe=data.get(
                "cwe",
                data.get(
                    "CWE"
                ),
            ),

            cve=data.get(
                "cve",
                data.get(
                    "CVE"
                ),
            ),

            references=data.get(
                "references",
                data.get(
                    "refs",
                    [],
                ),
            ),

            impact=data.get(
                "impact",
                "",
            ),

            remediation=data.get(
                "remediation",
                "",
            ),

            status=data.get(
                "status",
                data.get(
                    "finding_status",
                    DEFAULT_STATUS,
                ),
            ),

            metadata=data.get(
                "metadata",
                {},
            ),
        )

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the Finding into JSON-compatible data.
        """

        data = asdict(
            self
        )

        data["finding_id"] = (
            self.finding_id
        )

        data["timestamp"] = (
            self.timestamp.isoformat()
        )

        if hasattr(
            self.evidence,
            "as_dict",
        ):
            data["evidence"] = (
                self.evidence.as_dict()
            )

        return data

    def to_dict(
        self,
    ) -> dict[str, Any]:
        """
        Compatibility alias for as_dict().
        """

        return self.as_dict()

    ###########################################################################
    # Semantic Identity
    ###########################################################################

    def correlation_key(
        self,
    ) -> tuple[str, ...]:
        """
        Return a stable contextual key for correlation.

        Correlation identifies related findings on the same asset. It does
        not determine whether findings are duplicates.
        """

        return (
            _normalize_identity_text(
                self.host
            ),

            (
                str(
                    self.port
                )
                if self.port is not None
                else ""
            ),

            _normalize_identity_text(
                self.url
            ),

            _normalize_identity_text(
                self.parameter
            ),
        )

    def deduplication_key(
        self,
    ) -> tuple[str, ...]:
        """
        Return the semantic identity used for duplicate detection.

        Source tool, detection method, timestamp, severity, confidence,
        lifecycle status, evidence and metadata are intentionally excluded.
        """

        return (
            _normalize_identity_text(
                self.category
            ),

            _normalize_identity_text(
                self.title
            ),

            _normalize_identity_text(
                self.host
            ),

            (
                str(
                    self.port
                )
                if self.port is not None
                else ""
            ),

            _normalize_identity_text(
                self.url
            ),

            _normalize_identity_text(
                self.parameter
            ),
        )

    def fingerprint(
        self,
    ) -> str:
        """
        Return the deterministic semantic fingerprint.

        The fingerprint is derived exclusively from ``deduplication_key()``.
        """

        payload = json.dumps(
            self.deduplication_key(),
            ensure_ascii=False,
            separators=(
                ",",
                ":",
            ),
        )

        return hashlib.sha256(
            payload.encode(
                "utf-8"
            )
        ).hexdigest()

    ###########################################################################
    # Convenience Methods
    ###########################################################################

    def is_vulnerability(
        self,
    ) -> bool:
        """
        Return True for a non-informational finding.

        This does not imply manual validation or successful exploitation.
        """

        return self.severity != "Informational"

    def is_confirmed(
        self,
    ) -> bool:
        """
        Return True when confidence is explicitly Confirmed.
        """

        return self.confidence == "Confirmed"

    def add_reference(
        self,
        reference: str,
    ) -> None:
        """
        Add a unique reference.
        """

        reference = _text(
            reference
        )

        if not reference:
            return

        if reference not in self.references:
            self.references.append(
                reference
            )

    def add_evidence(
        self,
        evidence: Any,
    ) -> None:
        """
        Add evidence while preserving existing evidence.
        """

        if evidence is None:
            return

        if (
            isinstance(
                self.evidence,
                dict,
            )
            and isinstance(
                evidence,
                Mapping,
            )
        ):
            self.evidence.update(
                evidence
            )

            return

        if self.evidence in (
            "",
            None,
        ):
            self.evidence = evidence

            return

        if not isinstance(
            self.evidence,
            list,
        ):
            self.evidence = [
                self.evidence
            ]

        self.evidence.append(
            evidence
        )


###############################################################################
# Compatibility Factory
###############################################################################


def finding_from_mapping(
    data: Mapping[str, Any],
    *,
    finding_id: str | None = None,
) -> Finding:
    """
    Construct a canonical Finding from a mapping.
    """

    return Finding.from_mapping(
        data,
        finding_id=finding_id,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "Finding",
    "FindingEvidence",
    "finding_from_mapping",
    "utc_now",
    "DEFAULT_CATEGORY",
    "DEFAULT_SEVERITY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_STATUS",
    "FINDING_STATUS_PENDING",
    "FINDING_STATUS_CONFIRMED",
    "VALID_SEVERITIES",
    "VALID_CONFIDENCES",
    "VALID_STATUSES",
]
