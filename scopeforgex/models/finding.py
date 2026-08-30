"""
ScopeForgeX Universal Finding Model
===================================

Canonical finding representation used throughout ScopeForgeX.

The Finding model is the boundary between tool-specific observations and the
rest of the assessment framework.

Architecture
------------

Tool / Analyzer
        |
        v
Raw Evidence
        |
        v
Observation
        |
        v
Finding
        |
        +--> Correlation
        |
        +--> Deduplication
        |
        +--> Risk Classification
        |
        +--> Evidence Management
        |
        v
Reporting

Design Principles
-----------------

- Every assessment result uses one universal finding structure.
- A finding may represent a vulnerability or a meaningful assessment
  observation.
- Detection confidence is separate from severity.
- Detection is not automatically confirmation.
- Original evidence is preserved.
- Source tool is preserved.
- Detection method is preserved.
- Findings are suitable for correlation and deduplication.
- Findings remain independent from reporting.
- The model does not execute tools or perform network requests.

v1.3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from scopeforgex.runtime.enums import (
    Confidence,
    Severity,
)


###############################################################################
# Canonical Defaults
###############################################################################


DEFAULT_CATEGORY = "assessment_observation"

DEFAULT_SEVERITY = Severity.INFO.value

DEFAULT_CONFIDENCE = Confidence.INFORMATIONAL.value

FINDING_STATUS_PENDING = "pending"

FINDING_STATUS_CONFIRMED = "confirmed"

DEFAULT_STATUS = FINDING_STATUS_PENDING


###############################################################################
# Compatibility Helpers
###############################################################################


def utc_now() -> datetime:
    """
    Return the current UTC time as a timezone-aware datetime.
    """

    return datetime.now(
        timezone.utc
    )


###############################################################################
# Finding Evidence
###############################################################################


@dataclass(slots=True)
class FindingEvidence:
    """
    Structured evidence associated with a Finding.

    This compatibility model is intentionally lightweight. It provides a
    normalized container for analyzer-generated evidence while remaining
    JSON-compatible through ``as_dict()``.
    """

    description: str = ""

    request: str = ""

    response: str = ""

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    raw: Any = None

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize evidence fields after construction.
        """

        self.description = (
            str(
                self.description
            ).strip()
            if self.description is not None
            else ""
        )

        self.request = (
            str(
                self.request
            ).strip()
            if self.request is not None
            else ""
        )

        self.response = (
            str(
                self.response
            ).strip()
            if self.response is not None
            else ""
        )

        if not isinstance(
            self.metadata,
            dict,
        ):
            self.metadata = dict(
                self.metadata
            )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize structured evidence into a dictionary.
        """

        result: dict[str, Any] = {
            "description": self.description,
            "request": self.request,
            "response": self.response,
            "metadata": dict(
                self.metadata
            ),
        }

        if self.raw is not None:
            result["raw"] = self.raw

        return result


###############################################################################
# Finding
###############################################################################


@dataclass(slots=True)
class Finding:
    """
    Universal ScopeForgeX assessment finding.

    A Finding represents normalized assessment information.

    It may describe:

    - a vulnerability
    - a misconfiguration
    - an exposed resource
    - a discovered service
    - an endpoint
    - a technology
    - another meaningful assessment observation

    The model intentionally does not assume that every finding is a confirmed
    vulnerability.
    """

    finding_id: str = field(
        default_factory=lambda: str(
            uuid4()
        )
    )

    title: str = ""

    category: str = DEFAULT_CATEGORY

    severity: str = DEFAULT_SEVERITY

    confidence: str = DEFAULT_CONFIDENCE

    target: str = ""

    host: str | None = None

    port: int | None = None

    url: str | None = None

    parameter: str | None = None

    description: str = ""

    evidence: Any = None

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
    # Initialization
    ###########################################################################

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize and validate the finding after construction.
        """

        self.finding_id = self._required_text(
            self.finding_id,
            "finding_id",
        )

        self.title = (
            self._text(
                self.title
            )
            or "Assessment Observation"
        )

        self.category = (
            self._text(
                self.category
            )
            or DEFAULT_CATEGORY
        )

        self.severity = self._normalize_severity(
            self.severity
        )

        self.confidence = self._normalize_confidence(
            self.confidence
        )

        self.target = self._text(
            self.target
        )

        self.host = self._optional_text(
            self.host
        )

        self.port = self._normalize_port(
            self.port
        )

        self.url = self._optional_text(
            self.url
        )

        self.parameter = self._optional_text(
            self.parameter
        )

        self.description = self._text(
            self.description
        )

        self.source_tool = self._text(
            self.source_tool
        )

        self.detection_method = self._text(
            self.detection_method
        )

        self.cwe = self._optional_text(
            self.cwe
        )

        self.cve = self._optional_text(
            self.cve
        )

        self.references = self._normalize_references(
            self.references
        )

        self.impact = self._text(
            self.impact
        )

        self.remediation = self._text(
            self.remediation
        )

        self.status = (
            self._text(
                self.status
            )
            or DEFAULT_STATUS
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
        Serialize the finding into a JSON-compatible dictionary.

        Structured FindingEvidence objects are converted automatically.
        """

        evidence = self.evidence

        if isinstance(
            evidence,
            FindingEvidence,
        ):
            evidence = evidence.as_dict()

        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "evidence": evidence,
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "timestamp": self.timestamp.isoformat(),
            "cwe": self.cwe,
            "cve": self.cve,
            "references": list(
                self.references
            ),
            "impact": self.impact,
            "remediation": self.remediation,
            "status": self.status,
            "metadata": dict(
                self.metadata
            ),
        }

    ###########################################################################
    # Mapping Construction
    ###########################################################################

    @classmethod
    def from_mapping(
        cls,
        data: Mapping[str, Any],
    ) -> Finding:
        """
        Construct a Finding from a normalized mapping.

        This method accepts both canonical Finding field names and common
        aliases produced by collectors and native analyzers.
        """

        if not isinstance(
            data,
            Mapping,
        ):
            raise TypeError(
                "Finding data must be a mapping."
            )

        finding_id = data.get(
            "finding_id",
            data.get(
                "id"
            ),
        )

        title = data.get(
            "title",
            "",
        )

        if not title:
            finding_type = data.get(
                "finding_type",
                data.get(
                    "observation_type",
                    "",
                ),
            )

            title = cls._title_from_type(
                finding_type
            )

        timestamp = cls._parse_timestamp(
            data.get(
                "timestamp"
            )
        )

        kwargs: dict[str, Any] = {
            "finding_id": finding_id
            if finding_id
            else str(
                uuid4()
            ),
            "title": title,
            "category": data.get(
                "category",
                data.get(
                    "finding_type",
                    data.get(
                        "observation_type",
                        DEFAULT_CATEGORY,
                    ),
                ),
            ),
            "severity": data.get(
                "severity",
                DEFAULT_SEVERITY,
            ),
            "confidence": data.get(
                "confidence",
                DEFAULT_CONFIDENCE,
            ),
            "target": data.get(
                "target",
                "",
            ),
            "host": data.get(
                "host"
            ),
            "port": data.get(
                "port"
            ),
            "url": data.get(
                "url"
            ),
            "parameter": data.get(
                "parameter"
            ),
            "description": data.get(
                "description",
                "",
            ),
            "evidence": data.get(
                "evidence"
            ),
            "source_tool": data.get(
                "source_tool",
                data.get(
                    "source",
                    "",
                ),
            ),
            "detection_method": data.get(
                "detection_method",
                "",
            ),
            "cwe": data.get(
                "cwe",
                data.get(
                    "CWE"
                ),
            ),
            "cve": data.get(
                "cve",
                data.get(
                    "CVE"
                ),
            ),
            "references": data.get(
                "references",
                [],
            ),
            "impact": data.get(
                "impact",
                "",
            ),
            "remediation": data.get(
                "remediation",
                "",
            ),
            "status": data.get(
                "status",
                DEFAULT_STATUS,
            ),
            "metadata": data.get(
                "metadata",
                {},
            ),
        }

        if timestamp is not None:
            kwargs[
                "timestamp"
            ] = timestamp

        return cls(
            **kwargs
        )

    ###########################################################################
    # Evidence
    ###########################################################################

    def add_evidence(
        self,
        key: str,
        value: Any,
    ) -> None:
        """
        Add structured evidence without replacing existing evidence.

        If evidence is a FindingEvidence instance, it is first converted into
        a dictionary while preserving the original structured fields.
        """

        key = self._required_text(
            key,
            "evidence key",
        )

        if self.evidence is None:
            self.evidence = {}

        elif isinstance(
            self.evidence,
            FindingEvidence,
        ):
            self.evidence = (
                self.evidence.as_dict()
            )

        elif not isinstance(
            self.evidence,
            dict,
        ):
            self.evidence = {
                "raw": self.evidence,
            }

        self.evidence[
            key
        ] = value

    ###########################################################################
    # References
    ###########################################################################

    def add_reference(
        self,
        reference: str,
    ) -> None:
        """
        Add one reference if it is not already present.
        """

        reference = self._text(
            reference
        )

        if not reference:
            return

        if reference not in self.references:
            self.references.append(
                reference
            )

    ###########################################################################
    # Metadata
    ###########################################################################

    def add_metadata(
        self,
        key: str,
        value: Any,
    ) -> None:
        """
        Add or update one metadata field.
        """

        key = self._required_text(
            key,
            "metadata key",
        )

        self.metadata[
            key
        ] = value

    ###########################################################################
    # Classification Helpers
    ###########################################################################

    @property
    def is_vulnerability(
        self,
    ) -> bool:
        """
        Return whether the finding represents a vulnerability-oriented
        category.

        This is a category observation only and does not confirm exploitability.
        """

        vulnerability_categories = {
            "vulnerability",
            "security_issue",
            "server_vulnerability",
            "tls_vulnerability",
            "sql_injection",
            "xss",
            "ssti",
            "jwt_security_issue",
            "cors_misconfiguration",
            "security_header_misconfiguration",
            "http_method_misconfiguration",
            "insecure_cookie",
        }

        return self.category.lower() in (
            vulnerability_categories
        )

    @property
    def is_confirmed(
        self,
    ) -> bool:
        """
        Return whether the finding is marked as confirmed.
        """

        return (
            self.confidence
            == Confidence.CONFIRMED.value
            or self.status
            == FINDING_STATUS_CONFIRMED
        )

    ###########################################################################
    # Normalization
    ###########################################################################

    @staticmethod
    def _text(
        value: Any,
    ) -> str:
        """
        Normalize a value to stripped text.
        """

        if value is None:
            return ""

        return str(
            value
        ).strip()

    @classmethod
    def _required_text(
        cls,
        value: Any,
        field_name: str,
    ) -> str:
        """
        Normalize a required textual field.
        """

        value = cls._text(
            value
        )

        if not value:
            raise ValueError(
                f"{field_name} cannot be empty."
            )

        return value

    @classmethod
    def _optional_text(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize an optional textual field.
        """

        value = cls._text(
            value
        )

        return value or None

    @staticmethod
    def _normalize_port(
        value: Any,
    ) -> int | None:
        """
        Normalize a port value.
        """

        if value is None:
            return None

        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "Finding port cannot be a boolean."
            )

        try:
            port = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"Invalid finding port: {value}"
            ) from exc

        if not 1 <= port <= 65535:
            raise ValueError(
                f"Finding port must be between 1 and 65535: {port}"
            )

        return port

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """
        Normalize severity into canonical runtime values.
        """

        if isinstance(
            value,
            Severity,
        ):
            return value.value

        normalized = str(
            value
        ).strip().lower()

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

    @staticmethod
    def _normalize_confidence(
        value: Any,
    ) -> str:
        """
        Normalize confidence into canonical runtime values.
        """

        if isinstance(
            value,
            Confidence,
        ):
            return value.value

        normalized = str(
            value
        ).strip().lower()

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

    @staticmethod
    def _normalize_references(
        value: Any,
    ) -> list[str]:
        """
        Normalize references into a unique list of strings.
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
            (list, tuple, set),
        ):
            references: list[str] = []

            for item in value:
                item = str(
                    item
                ).strip()

                if (
                    item
                    and item not in references
                ):
                    references.append(
                        item
                    )

            return references

        value = str(
            value
        ).strip()

        return (
            [value]
            if value
            else []
        )

    ###########################################################################
    # Timestamp
    ###########################################################################

    @staticmethod
    def _parse_timestamp(
        value: Any,
    ) -> datetime | None:
        """
        Parse a timestamp into a datetime object.
        """

        if value is None:
            return None

        if isinstance(
            value,
            datetime,
        ):
            return value

        if isinstance(
            value,
            str,
        ):
            value = value.strip()

            if not value:
                return None

            try:
                return datetime.fromisoformat(
                    value
                )
            except ValueError:
                return None

        return None

    ###########################################################################
    # Title
    ###########################################################################

    @staticmethod
    def _title_from_type(
        finding_type: Any,
    ) -> str:
        """
        Generate a human-readable title from a finding type.
        """

        finding_type = str(
            finding_type
        ).strip()

        if not finding_type:
            return "Assessment Observation"

        return (
            finding_type
            .replace(
                "_",
                " ",
            )
            .title()
        )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "DEFAULT_CATEGORY",
    "DEFAULT_SEVERITY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_STATUS",
    "FINDING_STATUS_PENDING",
    "FINDING_STATUS_CONFIRMED",
    "Finding",
    "FindingEvidence",
    "utc_now",
]
