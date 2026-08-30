"""
ScopeForgeX Finding Normalizer
==============================

Normalization layer for converting heterogeneous collector and analyzer
observations into the canonical ScopeForgeX Finding model.

Responsibilities
----------------

- Accept mappings, Finding objects, and objects exposing ``as_dict()``.
- Convert analyzer/collector observations into Finding objects.
- Preserve source and detection information.
- Preserve observation-specific data in metadata.
- Apply consistent alias handling for severity, confidence, status and
  location fields.
- Avoid silently treating detection as confirmation.
- Keep normalization independent from correlation and deduplication.

The normalizer does not:

- Execute external tools.
- Perform network requests.
- Validate vulnerabilities.
- Deduplicate findings.
- Correlate findings.
- Generate reports.

Architecture
------------

Raw Observation
        |
        v
FindingNormalizer
        |
        v
Canonical Finding
        |
        +--> Confidence
        +--> Risk Classification
        +--> Deduplication
        +--> Correlation
        +--> Evidence Management
        |
        v
Reporting

The canonical ``Finding`` model remains the single source of truth for
validation, normalization, identifiers and serialization.

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

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


SEVERITY_ALIASES: dict[str, str] = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "moderate": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "information": Severity.INFO.value,
    "informational": Severity.INFO.value,
}


CONFIDENCE_ALIASES: dict[str, str] = {
    "confirmed": Confidence.CONFIRMED.value,
    "high": Confidence.HIGH.value,
    "medium": Confidence.MEDIUM.value,
    "low": Confidence.LOW.value,
    "info": Confidence.INFORMATIONAL.value,
    "information": Confidence.INFORMATIONAL.value,
    "informational": Confidence.INFORMATIONAL.value,
}


STATUS_ALIASES: dict[str, str] = {
    "open": "open",
    "pending": DEFAULT_STATUS,
    "unvalidated": DEFAULT_STATUS,
    "confirmed": "confirmed",
    "valid": "confirmed",
    "rejected": "rejected",
    "invalid": "rejected",
    "remediated": "remediated",
    "accepted": "accepted",
}


###############################################################################
# Generic Helpers
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

    normalized = _text(
        value
    )

    return normalized or None


def _severity(
    value: Any,
) -> str:
    """
    Normalize severity into the canonical runtime enum value.

    Unknown or missing values fall back to the canonical informational
    severity rather than allowing arbitrary values into the Finding model.
    """

    if isinstance(
        value,
        Severity,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    return SEVERITY_ALIASES.get(
        normalized,
        DEFAULT_SEVERITY,
    )


def _confidence(
    value: Any,
) -> str:
    """
    Normalize confidence into the canonical runtime enum value.

    Unknown or missing values fall back to informational confidence.
    """

    if isinstance(
        value,
        Confidence,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    return CONFIDENCE_ALIASES.get(
        normalized,
        DEFAULT_CONFIDENCE,
    )


def _status(
    value: Any,
) -> str:
    """
    Normalize a finding lifecycle status.

    Unknown values are preserved as normalized text so the normalizer does not
    silently reinterpret a custom lifecycle state.
    """

    normalized = _text(
        value
    ).lower()

    if not normalized:
        return DEFAULT_STATUS

    return STATUS_ALIASES.get(
        normalized,
        normalized,
    )


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
        normalized = value.strip()

        return (
            [normalized]
            if normalized
            else []
        )

    if isinstance(
        value,
        Iterable,
    ) and not isinstance(
        value,
        (bytes, bytearray),
    ):
        result: list[str] = []

        for item in value:
            normalized = _text(
                item
            )

            if (
                normalized
                and normalized not in result
            ):
                result.append(
                    normalized
                )

        return result

    normalized = _text(
        value
    )

    return (
        [normalized]
        if normalized
        else []
    )


def _port(
    value: Any,
) -> int | None:
    """
    Normalize a port value into an integer when possible.

    Invalid values remain ``None`` rather than being guessed.
    """

    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return None

    if isinstance(
        value,
        int,
    ):
        return value

    normalized = _text(
        value
    )

    if not normalized:
        return None

    try:
        return int(
            normalized
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


###############################################################################
# Finding Normalizer
###############################################################################


class FindingNormalizer:
    """
    Convert heterogeneous assessment observations into canonical Findings.

    The normalizer is intentionally conservative. It maps information already
    present in an observation rather than inventing security conclusions.

    Final Finding construction is delegated to ``Finding.from_mapping()`` so
    that the canonical model remains responsible for identifiers, field
    normalization and serialization.
    """

    name = "finding_normalizer"

    description = (
        "Normalize collector and analyzer observations into canonical "
        "ScopeForgeX findings."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def normalize(
        self,
        observation: Any,
    ) -> Finding:
        """
        Normalize one observation into a canonical Finding.

        Args:
            observation:
                A Finding, mapping, or object exposing ``as_dict()``.

        Returns:
            A canonical Finding.

        Raises:
            TypeError:
                If the observation cannot be represented as a mapping or
                Finding.
        """

        if isinstance(
            observation,
            Finding,
        ):
            return observation

        data = self._observation_mapping(
            observation
        )

        normalized = self._normalize_mapping(
            data
        )

        return Finding.from_mapping(
            normalized
        )

    def normalize_many(
        self,
        observations: Any,
    ) -> list[Finding]:
        """
        Normalize multiple observations.

        ``None`` produces an empty list.

        A single Finding, mapping, or object exposing ``as_dict()`` is treated
        as one observation. Other iterables are processed item by item.
        """

        if observations is None:
            return []

        if isinstance(
            observations,
            Finding,
        ):
            return [
                observations
            ]

        if isinstance(
            observations,
            Mapping,
        ):
            return [
                self.normalize(
                    observations
                )
            ]

        if hasattr(
            observations,
            "as_dict",
        ):
            return [
                self.normalize(
                    observations
                )
            ]

        if isinstance(
            observations,
            Iterable,
        ) and not isinstance(
            observations,
            (str, bytes, bytearray),
        ):
            findings: list[Finding] = []

            for observation in observations:
                findings.append(
                    self.normalize(
                        observation
                    )
                )

            return findings

        return [
            self.normalize(
                observations
            )
        ]

    ###########################################################################
    # Observation Conversion
    ###########################################################################

    @staticmethod
    def _observation_mapping(
        observation: Any,
    ) -> Mapping[str, Any]:
        """
        Convert an observation into a mapping.

        Objects exposing ``as_dict()`` are preferred because collector and
        analyzer observation models commonly provide that interface.
        """

        if isinstance(
            observation,
            Mapping,
        ):
            return observation

        serializer = getattr(
            observation,
            "as_dict",
            None,
        )

        if callable(
            serializer,
        ):
            data = serializer()

            if not isinstance(
                data,
                Mapping,
            ):
                raise TypeError(
                    "Observation as_dict() must return a mapping."
                )

            return data

        raise TypeError(
            "Observation must be a Finding, mapping, or expose as_dict()."
        )

    ###########################################################################
    # Mapping Normalization
    ###########################################################################

    def _normalize_mapping(
        self,
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a heterogeneous observation mapping into canonical Finding
        field names.

        Fields that are not part of the universal Finding model are retained
        in metadata rather than discarded.
        """

        source = dict(
            data
        )

        finding_type = self._first_value(
            source,
            (
                "finding_type",
                "observation_type",
                "type",
                "rule_id",
            ),
        )

        category = self._first_value(
            source,
            (
                "category",
                "finding_category",
                "classification",
            ),
        )

        if not category:
            category = finding_type

        category = (
            _text(
                category
            )
            or DEFAULT_CATEGORY
        )

        title = self._first_value(
            source,
            (
                "title",
                "name",
                "finding",
            ),
        )

        if not title:
            title = finding_type

        title = _text(
            title
        )

        if not title:
            title = category

        severity = self._first_value(
            source,
            (
                "severity",
                "risk",
                "priority",
            ),
        )

        confidence = self._first_value(
            source,
            (
                "confidence",
                "certainty",
            ),
        )

        status = self._first_value(
            source,
            (
                "status",
                "validation_status",
            ),
        )

        target = self._first_value(
            source,
            (
                "target",
                "target_name",
                "asset",
            ),
        )

        host = self._first_value(
            source,
            (
                "host",
                "hostname",
                "ip",
                "ip_address",
            ),
        )

        port = self._first_value(
            source,
            (
                "port",
                "port_number",
            ),
        )

        url = self._first_value(
            source,
            (
                "url",
                "endpoint",
            ),
        )

        parameter = self._first_value(
            source,
            (
                "parameter",
                "param",
                "parameter_name",
            ),
        )

        description = self._first_value(
            source,
            (
                "description",
                "details",
                "message",
            ),
        )

        evidence = source.get(
            "evidence"
        )

        source_tool = self._first_value(
            source,
            (
                "source_tool",
                "tool",
                "source",
            ),
        )

        detection_method = self._first_value(
            source,
            (
                "detection_method",
                "detector",
                "method",
            ),
        )

        cwe = self._first_value(
            source,
            (
                "cwe",
                "cwe_id",
                "CWE",
            ),
        )

        cve = self._first_value(
            source,
            (
                "cve",
                "cve_id",
                "CVE",
            ),
        )

        references = source.get(
            "references",
            source.get(
                "refs",
                [],
            ),
        )

        impact = self._first_value(
            source,
            (
                "impact",
                "business_impact",
            ),
        )

        remediation = self._first_value(
            source,
            (
                "remediation",
                "recommendation",
                "fix",
            ),
        )

        timestamp = source.get(
            "timestamp"
        )

        metadata = self._build_metadata(
            source
        )

        normalized: dict[str, Any] = {
            "title": title,
            "category": category,
            "severity": _severity(
                severity
            ),
            "confidence": _confidence(
                confidence
            ),
            "target": _text(
                target
            ),
            "host": _optional_text(
                host
            ),
            "port": _port(
                port
            ),
            "url": _optional_text(
                url
            ),
            "parameter": _optional_text(
                parameter
            ),
            "description": _text(
                description
            ),
            "evidence": evidence,
            "source_tool": _text(
                source_tool
            ),
            "detection_method": _text(
                detection_method
            ),
            "cwe": _optional_text(
                cwe
            ),
            "cve": _optional_text(
                cve
            ),
            "references": _references(
                references
            ),
            "impact": _text(
                impact
            ),
            "remediation": _text(
                remediation
            ),
            "status": _status(
                status
            ),
            "metadata": metadata,
        }

        # Preserve an existing finding ID when supplied. Otherwise the
        # canonical Finding model generates one.
        finding_id = self._first_value(
            source,
            (
                "finding_id",
                "id",
            ),
        )

        if finding_id:
            normalized[
                "finding_id"
            ] = _text(
                finding_id
            )

        if timestamp is not None:
            normalized[
                "timestamp"
            ] = timestamp

        return normalized

    ###########################################################################
    # Metadata
    ###########################################################################

    @staticmethod
    def _build_metadata(
        data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve observation-specific fields in Finding metadata.

        Universal Finding fields and their supported aliases are excluded
        because they already have dedicated locations.
        """

        canonical_fields = {
            "finding_id",
            "id",
            "title",
            "category",
            "severity",
            "confidence",
            "target",
            "target_name",
            "asset",
            "host",
            "hostname",
            "ip",
            "ip_address",
            "port",
            "port_number",
            "url",
            "endpoint",
            "parameter",
            "param",
            "parameter_name",
            "description",
            "details",
            "message",
            "evidence",
            "source_tool",
            "tool",
            "source",
            "detection_method",
            "detector",
            "method",
            "timestamp",
            "cwe",
            "cwe_id",
            "CWE",
            "cve",
            "cve_id",
            "CVE",
            "references",
            "refs",
            "impact",
            "business_impact",
            "remediation",
            "recommendation",
            "fix",
            "status",
            "validation_status",
            "finding_type",
            "observation_type",
            "type",
            "rule_id",
            "finding_category",
            "classification",
            "name",
            "finding",
            "risk",
            "priority",
            "certainty",
            "metadata",
        }

        metadata: dict[str, Any] = {}

        existing_metadata = data.get(
            "metadata"
        )

        if isinstance(
            existing_metadata,
            Mapping,
        ):
            metadata.update(
                existing_metadata
            )

        for key, value in data.items():

            if key in canonical_fields:
                continue

            metadata[str(key)] = value

        return metadata

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _first_value(
        data: Mapping[str, Any],
        keys: tuple[str, ...],
    ) -> Any:
        """
        Return the first meaningful value from a sequence of aliases.
        """

        for key in keys:

            if key not in data:
                continue

            value = data.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):
                if value.strip():
                    return value

                continue

            return value

        return ""


###############################################################################
# Convenience API
###############################################################################


def normalize_finding(
    observation: Any,
) -> Finding:
    """
    Normalize one observation using a default FindingNormalizer.
    """

    return FindingNormalizer().normalize(
        observation
    )


def normalize_findings(
    observations: Any,
) -> list[Finding]:
    """
    Normalize multiple observations using a default FindingNormalizer.
    """

    return FindingNormalizer().normalize_many(
        observations
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "FindingNormalizer",
    "normalize_finding",
    "normalize_findings",
]
