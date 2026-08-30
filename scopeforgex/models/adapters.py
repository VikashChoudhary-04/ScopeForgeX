"""
ScopeForgeX Finding Adapters
============================

Normalization adapters for converting ScopeForgeX collector observations and
native analyzer observations into the universal Finding model.

Architecture
------------

Raw Tool Output
        |
        v
Collector / Native Analyzer
        |
        v
Observation
        |
        v
Finding Adapter
        |
        v
Universal Finding
        |
        +--> Correlation
        +--> Deduplication
        +--> Risk Classification
        +--> Evidence Management
        |
        v
Reporting

Design Principles
-----------------

- Adapters normalize observations into the universal Finding model.
- Adapters do not execute external tools.
- Adapters do not perform network requests.
- Adapters do not correlate findings.
- Adapters do not deduplicate findings.
- Adapters do not perform final risk scoring.
- Original observation information is preserved.
- Source tool and detection method are retained.
- Detection confidence remains separate from severity.
- Analyzer/collector-specific schemas do not leak into the workflow.

v1.3.0
"""

from __future__ import annotations

from datetime import datetime
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


OBSERVATION_SEVERITY = {
    "critical": Severity.CRITICAL.value,
    "high": Severity.HIGH.value,
    "medium": Severity.MEDIUM.value,
    "moderate": Severity.MEDIUM.value,
    "low": Severity.LOW.value,
    "info": Severity.INFO.value,
    "informational": Severity.INFO.value,
}


OBSERVATION_CONFIDENCE = {
    "confirmed": Confidence.CONFIRMED.value,
    "high": Confidence.HIGH.value,
    "medium": Confidence.MEDIUM.value,
    "low": Confidence.LOW.value,
    "info": Confidence.INFORMATIONAL.value,
    "informational": Confidence.INFORMATIONAL.value,
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

    value = _text(
        value
    )

    return value or None


def _severity(
    value: Any,
) -> str:
    """
    Normalize severity into the canonical Finding values.
    """

    if isinstance(
        value,
        Severity,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    return OBSERVATION_SEVERITY.get(
        normalized,
        DEFAULT_SEVERITY,
    )


def _confidence(
    value: Any,
) -> str:
    """
    Normalize confidence into the canonical Finding values.
    """

    if isinstance(
        value,
        Confidence,
    ):
        return value.value

    normalized = _text(
        value
    ).lower()

    return OBSERVATION_CONFIDENCE.get(
        normalized,
        DEFAULT_CONFIDENCE,
    )


def _references(
    value: Any,
) -> list[str]:
    """
    Normalize references into a unique list.
    """

    if value is None:
        return []

    if isinstance(
        value,
        str,
    ):
        value = value.strip()

        return [value] if value else []

    if isinstance(
        value,
        Iterable,
    ) and not isinstance(
        value,
        (str, bytes, Mapping),
    ):
        result: list[str] = []

        for item in value:

            item = _text(
                item
            )

            if item and item not in result:
                result.append(
                    item
                )

        return result

    value = _text(
        value
    )

    return [value] if value else []


def _timestamp(
    value: Any,
) -> datetime | None:
    """
    Normalize a timestamp value.

    Invalid or absent timestamps return None so the Finding model can use its
    normal default timestamp.
    """

    if isinstance(
        value,
        datetime,
    ):
        return value

    if isinstance(
        value,
        str,
    ):
        try:
            return datetime.fromisoformat(
                value
            )
        except ValueError:
            return None

    return None


def _metadata(
    observation: Any,
) -> dict[str, Any]:
    """
    Extract observation metadata without mutating the source object.
    """

    value = getattr(
        observation,
        "metadata",
        {},
    )

    if isinstance(
        value,
        Mapping,
    ):
        return dict(
            value
        )

    return {}


###############################################################################
# Observation ID
###############################################################################


def observation_id(
    observation: Any,
    prefix: str = "SF",
) -> str:
    """
    Return a stable finding identifier for an observation.

    The adapter does not perform deduplication. The identifier is based on
    information already present in the observation and is intended to provide
    a deterministic identity before correlation/deduplication occurs.

    When the observation already provides an ID, it is preserved.
    """

    existing_id = getattr(
        observation,
        "finding_id",
        None,
    )

    if existing_id:
        return _text(
            existing_id
        )

    existing_id = getattr(
        observation,
        "id",
        None,
    )

    if existing_id:
        return _text(
            existing_id
        )

    metadata = _metadata(
        observation
    )

    metadata_id = metadata.get(
        "finding_id"
    )

    if metadata_id:
        return _text(
            metadata_id
        )

    observation_type = _text(
        getattr(
            observation,
            "observation_type",
            getattr(
                observation,
                "finding_type",
                "observation",
            ),
        )
    )

    value = _text(
        getattr(
            observation,
            "value",
            "",
        )
    )

    source_tool = _text(
        getattr(
            observation,
            "source_tool",
            "",
        )
    )

    if not observation_type:
        observation_type = "observation"

    components = [
        prefix,
        source_tool or "scopeforgex",
        observation_type,
    ]

    if value:
        components.append(
            value
        )

    normalized = "-".join(
        component.replace(
            " ",
            "_",
        )
        for component in components
        if component
    )

    return normalized


###############################################################################
# Collector Observation Adapter
###############################################################################


def collector_observation_to_finding(
    observation: Any,
    finding_id: str | None = None,
) -> Finding:
    """
    Convert a CollectorObservation into a universal Finding.

    The adapter accepts the canonical CollectorObservation structure while
    remaining tolerant of compatible observation objects.

    Observation fields are mapped as follows:

        observation_type -> category
        value            -> evidence/value
        target           -> target
        host             -> host
        port             -> port
        url              -> url
        parameter        -> parameter
        evidence         -> evidence
        source_tool      -> source_tool
        detection_method -> detection_method
        confidence       -> confidence
        metadata         -> metadata

    Severity is taken from metadata when explicitly provided. Otherwise the
    normalized default severity is used.

    Detection observations are not automatically marked confirmed.
    """

    if observation is None:
        raise TypeError(
            "Collector observation cannot be None."
        )

    observation_type = _text(
        getattr(
            observation,
            "observation_type",
            "",
        )
    )

    if not observation_type:
        raise ValueError(
            "Collector observation must define observation_type."
        )

    target = _text(
        getattr(
            observation,
            "target",
            "",
        )
    )

    host = _optional_text(
        getattr(
            observation,
            "host",
            None,
        )
    )

    port = getattr(
        observation,
        "port",
        None,
    )

    url = _optional_text(
        getattr(
            observation,
            "url",
            None,
        )
    )

    parameter = _optional_text(
        getattr(
            observation,
            "parameter",
            None,
        )
    )

    source_tool = _text(
        getattr(
            observation,
            "source_tool",
            "",
        )
    )

    detection_method = _text(
        getattr(
            observation,
            "detection_method",
            "",
        )
    )

    confidence = _confidence(
        getattr(
            observation,
            "confidence",
            DEFAULT_CONFIDENCE,
        )
    )

    metadata = _metadata(
        observation
    )

    severity = _severity(
        metadata.get(
            "severity",
            DEFAULT_SEVERITY,
        )
    )

    title = _text(
        metadata.get(
            "title",
            observation_type.replace(
                "_",
                " ",
            ).title(),
        )
    )

    description = _text(
        metadata.get(
            "description",
            f"{observation_type} was identified during the assessment.",
        )
    )

    impact = _text(
        metadata.get(
            "impact",
            "",
        )
    )

    remediation = _text(
        metadata.get(
            "remediation",
            "",
        )
    )

    cwe = _optional_text(
        metadata.get(
            "cwe",
            metadata.get(
                "CWE"
            ),
        )
    )

    cve = _optional_text(
        metadata.get(
            "cve",
            metadata.get(
                "CVE"
            ),
        )
    )

    references = _references(
        metadata.get(
            "references",
            [],
        )
    )

    status = _text(
        metadata.get(
            "status",
            DEFAULT_STATUS,
        )
    )

    evidence = getattr(
        observation,
        "evidence",
        None,
    )

    if evidence is None:

        value = getattr(
            observation,
            "value",
            None,
        )

        if value is not None:
            evidence = {
                "value": value,
            }

    metadata = dict(
        metadata
    )

    metadata.setdefault(
        "observation_type",
        observation_type,
    )

    value = getattr(
        observation,
        "value",
        None,
    )

    if value is not None:
        metadata.setdefault(
            "observation_value",
            value,
        )

    timestamp = _timestamp(
        metadata.get(
            "timestamp"
        )
    )

    finding_kwargs: dict[str, Any] = {
        "finding_id": (
            finding_id
            or observation_id(
                observation
            )
        ),
        "title": title,
        "category": observation_type
        or DEFAULT_CATEGORY,
        "severity": severity,
        "confidence": confidence,
        "target": target,
        "host": host,
        "port": port,
        "url": url,
        "parameter": parameter,
        "description": description,
        "evidence": evidence,
        "source_tool": source_tool,
        "detection_method": detection_method,
        "cwe": cwe,
        "cve": cve,
        "references": references,
        "impact": impact,
        "remediation": remediation,
        "status": status,
        "metadata": metadata,
    }

    if timestamp is not None:
        finding_kwargs[
            "timestamp"
        ] = timestamp

    return Finding(
        **finding_kwargs
    )


###############################################################################
# Mapping Adapter
###############################################################################


def mapping_to_finding(
    data: Mapping[str, Any],
    finding_id: str | None = None,
) -> Finding:
    """
    Convert a normalized mapping into a universal Finding.

    This is useful for native analyzers or collectors that expose their
    observation through a dictionary rather than a CollectorObservation
    instance.

    The mapping is normalized through Finding.from_mapping().
    """

    if not isinstance(
        data,
        Mapping,
    ):
        raise TypeError(
            "Finding input must be a mapping."
        )

    normalized = dict(
        data
    )

    if finding_id is not None:
        normalized[
            "finding_id"
        ] = finding_id

    if not normalized.get(
        "finding_id"
    ):
        normalized[
            "finding_id"
        ] = _mapping_finding_id(
            normalized
        )

    if not normalized.get(
        "title"
    ):
        finding_type = _text(
            normalized.get(
                "finding_type",
                normalized.get(
                    "observation_type",
                    "assessment observation",
                ),
            )
        )

        normalized[
            "title"
        ] = (
            finding_type.replace(
                "_",
                " ",
            ).title()
            if finding_type
            else "Assessment Observation"
        )

    if not normalized.get(
        "category"
    ):
        normalized[
            "category"
        ] = _text(
            normalized.get(
                "finding_type",
                normalized.get(
                    "observation_type",
                    DEFAULT_CATEGORY,
                ),
            )
        ) or DEFAULT_CATEGORY

    if "severity" in normalized:
        normalized[
            "severity"
        ] = _severity(
            normalized[
                "severity"
            ]
        )

    if "confidence" in normalized:
        normalized[
            "confidence"
        ] = _confidence(
            normalized[
                "confidence"
            ]
        )

    return Finding.from_mapping(
        normalized
    )


def _mapping_finding_id(
    data: Mapping[str, Any],
) -> str:
    """
    Build a deterministic identifier from a normalized mapping.
    """

    source_tool = _text(
        data.get(
            "source_tool",
            data.get(
                "source",
                "scopeforgex",
            ),
        )
    )

    finding_type = _text(
        data.get(
            "finding_type",
            data.get(
                "observation_type",
                "observation",
            ),
        )
    )

    value = data.get(
        "value"
    )

    if value is None:
        value = data.get(
            "url",
            data.get(
                "target",
                "",
            ),
        )

    value = _text(
        value
    )

    parts = [
        "SF",
        source_tool or "scopeforgex",
        finding_type or "observation",
    ]

    if value:
        parts.append(
            value
        )

    return "-".join(
        part.replace(
            " ",
            "_",
        )
        for part in parts
        if part
    )


###############################################################################
# Batch Normalization
###############################################################################


def normalize_observations(
    observations: Iterable[Any],
) -> list[Finding]:
    """
    Normalize a sequence of collector/native observations.

    This function deliberately performs no deduplication. If two observations
    describe the same underlying issue, both remain present for the later
    correlation and deduplication stages.
    """

    findings: list[Finding] = []

    for observation in observations:

        if observation is None:
            continue

        if isinstance(
            observation,
            Mapping,
        ):

            findings.append(
                mapping_to_finding(
                    observation
                )
            )

            continue

        findings.append(
            collector_observation_to_finding(
                observation
            )
        )

    return findings


###############################################################################
# Public API
###############################################################################


__all__ = [
    "collector_observation_to_finding",
    "mapping_to_finding",
    "normalize_observations",
    "observation_id",
]
