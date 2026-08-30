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
- A finding may represent a vulnerability, security issue, configuration
  issue, credential assessment result, or attack-surface observation.
- Detection does not automatically mean confirmed exploitation.
- Confidence is independent from severity.
- Evidence is preserved as structured data.
- Optional fields remain optional rather than being populated with guesses.
- The model is serializable and suitable for JSON/reporting pipelines.
- The model contains no execution or network logic.

v1.0.0
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


###############################################################################
# Constants
###############################################################################


DEFAULT_SEVERITY = "Informational"
DEFAULT_CONFIDENCE = "Informational"
DEFAULT_STATUS = "Open"

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
# Helpers
###############################################################################


def _text(value: Any) -> str:
    """Return a normalized string representation."""

    if value is None:
        return ""

    return str(value).strip()


def _optional_text(value: Any) -> str | None:
    """Return normalized text or None when empty."""

    normalized = _text(value)

    return normalized or None


def _normalize_severity(value: Any) -> str:
    """
    Normalize a severity value.

    Unknown or missing values become Informational rather than being
    silently promoted to a higher risk level.
    """

    normalized = _text(value)

    if not normalized:
        return DEFAULT_SEVERITY

    lookup = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }

    return lookup.get(
        normalized.lower(),
        DEFAULT_SEVERITY,
    )


def _normalize_confidence(value: Any) -> str:
    """
    Normalize a confidence value.

    Confidence is deliberately independent from severity.
    """

    normalized = _text(value)

    if not normalized:
        return DEFAULT_CONFIDENCE

    lookup = {
        "confirmed": "Confirmed",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Informational",
        "informational": "Informational",
    }

    return lookup.get(
        normalized.lower(),
        DEFAULT_CONFIDENCE,
    )


def _normalize_status(value: Any) -> str:
    """Normalize a finding lifecycle status."""

    normalized = _text(value)

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


def _normalize_port(value: Any) -> int | None:
    """Convert a port value into an integer when possible."""

    if value is None or value == "":
        return None

    try:
        port = int(value)
    except (TypeError, ValueError):
        return None

    if 0 <= port <= 65535:
        return port

    return None


def _normalize_references(
    value: Any,
) -> list[str]:
    """Normalize references into a unique ordered list."""

    if value is None:
        return []

    if isinstance(value, str):
        value = [value]

    try:
        iterator = iter(value)
    except TypeError:
        value = [value]
        iterator = iter(value)

    references: list[str] = []
    seen: set[str] = set()

    for item in iterator:
        reference = _text(item)

        if not reference or reference in seen:
            continue

        seen.add(reference)
        references.append(reference)

    return references


def _normalize_evidence(
    value: Any,
) -> Any:
    """
    Normalize evidence while preserving its structure.

    Evidence may be a string, mapping, list, or another JSON-compatible
    structure. It is intentionally not flattened because collectors may
    provide structured evidence.
    """

    if value is None:
        return ""

    if isinstance(value, Mapping):
        return dict(value)

    if isinstance(value, list):
        return list(value)

    if isinstance(value, tuple):
        return list(value)

    return value


def _normalize_timestamp(
    value: Any,
) -> datetime:
    """
    Normalize a timestamp.

    Missing timestamps use the current UTC time. Naive datetimes are treated
    as UTC so the model has a consistent temporal representation.
    """

    if isinstance(value, datetime):

        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value

    if isinstance(value, str):
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

                return parsed

            except ValueError:
                pass

    return datetime.now(
        timezone.utc
    )


###############################################################################
# Universal Finding
###############################################################################


@dataclass(slots=True)
class Finding:
    """
    Universal normalized ScopeForgeX finding.

    A Finding is the canonical representation consumed by correlation,
    deduplication, risk classification, evidence handling, and reporting.

    The model intentionally supports both traditional security findings
    and meaningful assessment observations.

    Examples
    --------

    A network observation:

        Finding(
            id="SF-001",
            title="Open SSH Port",
            category="OPEN_PORT",
            severity="Informational",
            confidence="High",
            target="example.com",
            host="192.0.2.10",
            port=22,
            source_tool="nmap",
        )

    A vulnerability:

        Finding(
            id="SF-002",
            title="SQL Injection",
            category="SQL_INJECTION",
            severity="High",
            confidence="Confirmed",
            target="https://example.com",
            url="https://example.com/search",
            parameter="q",
            source_tool="sqlmap",
        )
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
        default_factory=lambda: datetime.now(
            timezone.utc
        )
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
    # Initialization
    ###########################################################################

    def __post_init__(self) -> None:
        """Normalize externally supplied values."""

        self.id = _text(self.id)

        self.title = _text(self.title)

        self.category = _text(
            self.category
        )

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
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the finding into a JSON-friendly dictionary.

        Datetime values are represented using ISO-8601 notation.
        """

        data = asdict(
            self
        )

        data["timestamp"] = (
            self.timestamp.isoformat()
        )

        return data

    def to_dict(
        self,
    ) -> dict[str, Any]:
        """Compatibility alias for as_dict()."""

        return self.as_dict()

    ###########################################################################
    # Identity / Correlation
    ###########################################################################

    def correlation_key(
        self,
    ) -> tuple[str, ...]:
        """
        Return a stable contextual key for correlation.

        This is intentionally not the final deduplication key. Multiple
        findings may legitimately exist on the same asset.

        The key captures the primary affected location.
        """

        return (
            _text(self.host),
            str(
                self.port
            )
            if self.port is not None
            else "",
            _text(self.url),
            _text(self.parameter),
        )

    def deduplication_key(
        self,
    ) -> tuple[str, ...]:
        """
        Return a stable key suitable for duplicate detection.

        Source tool and timestamp are intentionally excluded so that the same
        underlying issue reported by multiple tools can be correlated.
        """

        return (
            _text(self.category).lower(),
            _text(self.title).lower(),
            _text(self.host).lower(),
            str(
                self.port
            )
            if self.port is not None
            else "",
            _text(self.url).lower(),
            _text(self.parameter).lower(),
        )

    ###########################################################################
    # Convenience helpers
    ###########################################################################

    def is_vulnerability(
        self,
    ) -> bool:
        """
        Return True when the finding represents a non-informational issue.

        This is a classification convenience method, not a claim that the
        issue has been manually validated.
        """

        return self.severity != "Informational"

    def is_confirmed(
        self,
    ) -> bool:
        """Return True when confidence is explicitly Confirmed."""

        return self.confidence == "Confirmed"

    def add_reference(
        self,
        reference: str,
    ) -> None:
        """Add a reference without creating duplicates."""

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

        Mapping evidence is merged. Other evidence types are appended to a
        list when necessary.
        """

        if evidence is None:
            return

        if isinstance(
            self.evidence,
            dict,
        ) and isinstance(
            evidence,
            Mapping,
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
# Factory
###############################################################################


def finding_from_mapping(
    data: Mapping[str, Any],
    *,
    finding_id: str | None = None,
) -> Finding:
    """
    Construct a Finding from a collector/analyzer mapping.

    This helper intentionally performs only field mapping and normalization.
    It does not contain tool-specific parsing rules.
    """

    if not isinstance(
        data,
        Mapping,
    ):
        raise TypeError(
            "Finding data must be a mapping."
        )

    resolved_id = (
        finding_id
        or data.get("id")
        or data.get("finding_id")
        or ""
    )

    if not _text(
        resolved_id
    ):
        raise ValueError(
            "A finding ID is required."
        )

    category = (
        data.get(
            "category"
        )
        or data.get(
            "finding_type"
        )
        or "ASSESSMENT_OBSERVATION"
    )

    return Finding(
        id=_text(
            resolved_id
        ),
        title=_text(
            data.get(
                "title",
                "Untitled Finding",
            )
        ),
        category=_text(
            category
        ),
        severity=data.get(
            "severity",
            DEFAULT_SEVERITY,
        ),
        confidence=data.get(
            "confidence",
            DEFAULT_CONFIDENCE,
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
                "tool",
                "",
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
            [],
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
            DEFAULT_STATUS,
        ),
        metadata=data.get(
            "metadata",
            {},
        ),
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "Finding",
    "finding_from_mapping",
    "DEFAULT_SEVERITY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_STATUS",
    "VALID_SEVERITIES",
    "VALID_CONFIDENCES",
    "VALID_STATUSES",
]
