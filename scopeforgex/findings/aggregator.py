"""
ScopeForgeX Finding Aggregator
==============================

Aggregation layer for canonical ScopeForgeX Findings.

The aggregator collects Findings from multiple assessment stages, normalizes
their container representation, preserves the original Finding objects, and
provides deterministic summary information for downstream workflow stages.

Responsibilities
----------------

- Collect canonical Finding objects.
- Add findings incrementally.
- Normalize batches of findings.
- Preserve Finding object identity.
- Provide deterministic ordering.
- Filter findings by common attributes.
- Produce aggregate statistics.
- Serialize aggregate results.
- Remain independent from deduplication and correlation.

The aggregator does not:

- Execute external tools.
- Perform network requests.
- Validate vulnerabilities.
- Deduplicate findings.
- Correlate findings.
- Modify Finding objects.
- Generate final reports.

Architecture
------------

Collectors / Analyzers
        |
        v
FindingNormalizer
        |
        v
FindingAggregator
        |
        +--> Finding collection
        +--> Statistics
        +--> Filters
        +--> Reporting input
        |
        +--> Deduplicator
        +--> Correlator
        +--> Risk classification

v1.3.0
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .model import Finding
from .normalizer import FindingNormalizer


###############################################################################
# Constants
###############################################################################


AGGREGATE_TOTAL = "total"
AGGREGATE_BY_SEVERITY = "by_severity"
AGGREGATE_BY_CONFIDENCE = "by_confidence"
AGGREGATE_BY_STATUS = "by_status"
AGGREGATE_BY_CATEGORY = "by_category"
AGGREGATE_BY_SOURCE = "by_source"
AGGREGATE_BY_DETECTION_METHOD = "by_detection_method"


###############################################################################
# Finding Aggregator
###############################################################################


class FindingAggregator:
    """
    Collect and summarize canonical ScopeForgeX Findings.

    The aggregator acts as a lightweight in-memory collection. It does not
    create a second Finding representation and does not alter Findings when
    they are added.

    Findings are normalized when necessary, allowing collectors and analyzers
    to provide heterogeneous observation mappings while keeping the
    aggregation layer canonical.
    """

    name = "finding_aggregator"

    description = (
        "Collect canonical ScopeForgeX findings and provide deterministic "
        "filtering and aggregate statistics."
    )

    def __init__(
        self,
        findings: Iterable[Any] | None = None,
        *,
        normalizer: FindingNormalizer | None = None,
    ) -> None:
        """
        Initialize the aggregator.

        Args:
            findings:
                Optional initial collection of Findings or observations.

            normalizer:
                Optional FindingNormalizer instance used for non-canonical
                observations.
        """

        self.normalizer = (
            normalizer
            if normalizer is not None
            else FindingNormalizer()
        )

        self._findings: list[Finding] = []
        self._finding_ids: set[str] = set()

        if findings is not None:
            self.add_many(
                findings
            )

    ###########################################################################
    # Collection Management
    ###########################################################################

    @property
    def findings(self) -> list[Finding]:
        """
        Return the current Finding collection.

        A new list is returned so callers cannot modify the aggregator's
        internal collection accidentally. The Finding objects themselves are
        intentionally not copied.
        """

        return list(
            self._findings
        )

    def __len__(
        self,
    ) -> int:
        """
        Return the number of aggregated Findings.
        """

        return len(
            self._findings
        )

    def __iter__(
        self,
    ):
        """
        Iterate over aggregated Findings in insertion order.
        """

        return iter(
            self._findings
        )

    def add(
        self,
        finding: Any,
    ) -> Finding:
        """
        Add one Finding or observation.

        Existing Finding identifiers are not inserted twice.

        Returns:
            The canonical Finding object stored by the aggregator.
        """

        normalized = self._normalize(
            finding
        )

        finding_id = normalized.finding_id

        if finding_id not in self._finding_ids:
            self._findings.append(
                normalized
            )

            self._finding_ids.add(
                finding_id
            )
        else:
            normalized = self._existing(
                finding_id
            )

        return normalized

    def add_many(
        self,
        findings: Iterable[Any],
    ) -> list[Finding]:
        """
        Add multiple Findings or observations.

        Returns:
            Canonical Finding objects corresponding to the supplied input.
        """

        if findings is None:
            return []

        if isinstance(
            findings,
            Finding,
        ):
            return [
                self.add(
                    findings
                )
            ]

        if isinstance(
            findings,
            Mapping,
        ):
            return [
                self.add(
                    findings
                )
            ]

        if hasattr(
            findings,
            "as_dict",
        ):
            return [
                self.add(
                    findings
                )
            ]

        result: list[Finding] = []

        for finding in findings:
            result.append(
                self.add(
                    finding
                )
            )

        return result

    def extend(
        self,
        findings: Iterable[Any],
    ) -> list[Finding]:
        """
        Alias for add_many().
        """

        return self.add_many(
            findings
        )

    def remove(
        self,
        finding_id: str,
    ) -> bool:
        """
        Remove a Finding by identifier.

        Returns:
            True when a Finding was removed, otherwise False.
        """

        finding_id = self._text(
            finding_id
        )

        if not finding_id:
            return False

        for index, finding in enumerate(
            self._findings
        ):
            if finding.finding_id != finding_id:
                continue

            self._findings.pop(
                index
            )

            self._finding_ids.discard(
                finding_id
            )

            return True

        return False

    def clear(
        self,
    ) -> None:
        """
        Remove all aggregated Findings.
        """

        self._findings.clear()
        self._finding_ids.clear()

    ###########################################################################
    # Lookup
    ###########################################################################

    def get(
        self,
        finding_id: str,
    ) -> Finding | None:
        """
        Return a Finding by identifier.

        Returns:
            The Finding object or None when it does not exist.
        """

        finding_id = self._text(
            finding_id
        )

        if not finding_id:
            return None

        return self._existing(
            finding_id
        )

    def require(
        self,
        finding_id: str,
    ) -> Finding:
        """
        Return a Finding by identifier.

        Raises:
            KeyError:
                If the identifier does not exist.
        """

        finding = self.get(
            finding_id
        )

        if finding is None:
            raise KeyError(
                f"Finding not found: {finding_id!r}"
            )

        return finding

    ###########################################################################
    # Filtering
    ###########################################################################

    def filter(
        self,
        *,
        severity: str | None = None,
        confidence: str | None = None,
        status: str | None = None,
        category: str | None = None,
        source_tool: str | None = None,
        detection_method: str | None = None,
        target: str | None = None,
        host: str | None = None,
        url: str | None = None,
    ) -> list[Finding]:
        """
        Filter Findings by common canonical attributes.

        All supplied filters are combined using logical AND.

        String comparisons are case-insensitive and whitespace-normalized.
        """

        filters = {
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "category": category,
            "source_tool": source_tool,
            "detection_method": detection_method,
            "target": target,
            "host": host,
            "url": url,
        }

        normalized_filters = {
            key: self._text(
                value
            ).lower()
            for key, value in filters.items()
            if value is not None
        }

        result: list[Finding] = []

        for finding in self._findings:
            matched = True

            for field_name, expected in normalized_filters.items():
                actual = self._text(
                    getattr(
                        finding,
                        field_name,
                        "",
                    )
                ).lower()

                if actual != expected:
                    matched = False
                    break

            if matched:
                result.append(
                    finding
                )

        return result

    def by_severity(
        self,
        severity: str,
    ) -> list[Finding]:
        """
        Return Findings matching one severity.
        """

        return self.filter(
            severity=severity
        )

    def by_category(
        self,
        category: str,
    ) -> list[Finding]:
        """
        Return Findings matching one category.
        """

        return self.filter(
            category=category
        )

    def by_status(
        self,
        status: str,
    ) -> list[Finding]:
        """
        Return Findings matching one lifecycle status.
        """

        return self.filter(
            status=status
        )

    def by_confidence(
        self,
        confidence: str,
    ) -> list[Finding]:
        """
        Return Findings matching one confidence level.
        """

        return self.filter(
            confidence=confidence
        )

    ###########################################################################
    # Ordering
    ###########################################################################

    def sorted(
        self,
        *,
        key: str = "timestamp",
        reverse: bool = False,
    ) -> list[Finding]:
        """
        Return Findings sorted by a canonical Finding attribute.

        The internal collection is not modified.

        Raises:
            ValueError:
                If the requested attribute does not exist on Finding.
        """

        if not hasattr(
            Finding,
            key,
        ) and not any(
            hasattr(
                finding,
                key,
            )
            for finding in self._findings
        ):
            raise ValueError(
                f"Unsupported Finding sort field: {key!r}"
            )

        return sorted(
            self._findings,
            key=lambda finding: self._sort_value(
                getattr(
                    finding,
                    key,
                    None,
                )
            ),
            reverse=reverse,
        )

    ###########################################################################
    # Statistics
    ###########################################################################

    def statistics(
        self,
    ) -> dict[str, Any]:
        """
        Produce aggregate statistics for the current Finding collection.

        Returns:
            A deterministic dictionary containing total count and counts
            grouped by severity, confidence, status, category, source and
            detection method.
        """

        return {
            AGGREGATE_TOTAL: len(
                self._findings
            ),
            AGGREGATE_BY_SEVERITY: self._count_by(
                "severity"
            ),
            AGGREGATE_BY_CONFIDENCE: self._count_by(
                "confidence"
            ),
            AGGREGATE_BY_STATUS: self._count_by(
                "status"
            ),
            AGGREGATE_BY_CATEGORY: self._count_by(
                "category"
            ),
            AGGREGATE_BY_SOURCE: self._count_by(
                "source_tool"
            ),
            AGGREGATE_BY_DETECTION_METHOD: self._count_by(
                "detection_method"
            ),
        }

    def count(
        self,
        *,
        severity: str | None = None,
        confidence: str | None = None,
        status: str | None = None,
        category: str | None = None,
    ) -> int:
        """
        Count Findings matching the supplied filters.
        """

        return len(
            self.filter(
                severity=severity,
                confidence=confidence,
                status=status,
                category=category,
            )
        )

    def severity_counts(
        self,
    ) -> dict[str, int]:
        """
        Return Finding counts grouped by severity.
        """

        return self._count_by(
            "severity"
        )

    def category_counts(
        self,
    ) -> dict[str, int]:
        """
        Return Finding counts grouped by category.
        """

        return self._count_by(
            "category"
        )

    ###########################################################################
    # Conversion
    ###########################################################################

    def to_list(
        self,
    ) -> list[Finding]:
        """
        Return the aggregated Finding objects in insertion order.
        """

        return self.findings

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the aggregate into a dictionary.

        Finding serialization uses the canonical Finding API when available.
        """

        return {
            "findings": [
                self._serialize_finding(
                    finding
                )
                for finding in self._findings
            ],
            "statistics": self.statistics(),
        }

    ###########################################################################
    # Internal Helpers
    ###########################################################################

    def _normalize(
        self,
        finding: Any,
    ) -> Finding:
        """
        Normalize one input object into a canonical Finding.
        """

        return self.normalizer.normalize(
            finding
        )

    def _existing(
        self,
        finding_id: str,
    ) -> Finding | None:
        """
        Locate an existing Finding by identifier.
        """

        for finding in self._findings:
            if finding.finding_id == finding_id:
                return finding

        return None

    def _count_by(
        self,
        field_name: str,
    ) -> dict[str, int]:
        """
        Count Findings by a canonical attribute.

        Empty values are represented by the explicit ``unknown`` bucket rather
        than being silently discarded.
        """

        counts: Counter[str] = Counter()

        for finding in self._findings:
            value = getattr(
                finding,
                field_name,
                None,
            )

            normalized = self._text(
                value
            )

            if not normalized:
                normalized = "unknown"

            counts[
                normalized
            ] += 1

        return dict(
            sorted(
                counts.items(),
                key=lambda item: item[0].lower(),
            )
        )

    @staticmethod
    def _sort_value(
        value: Any,
    ) -> tuple[int, str]:
        """
        Produce a stable sortable representation.
        """

        if value is None:
            return (
                0,
                "",
            )

        if hasattr(
            value,
            "isoformat",
        ):
            try:
                return (
                    1,
                    value.isoformat(),
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        return (
            1,
            str(
                value
            ),
        )

    @staticmethod
    def _serialize_finding(
        finding: Finding,
    ) -> dict[str, Any]:
        """
        Serialize one canonical Finding.
        """

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
            "timestamp": (
                finding.timestamp.isoformat()
                if finding.timestamp is not None
                else None
            ),
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

    @staticmethod
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


###############################################################################
# Convenience API
###############################################################################


def aggregate_findings(
    findings: Iterable[Any],
) -> FindingAggregator:
    """
    Aggregate a collection of Findings or observations.
    """

    return FindingAggregator(
        findings
    )


def aggregate_statistics(
    findings: Iterable[Any],
) -> dict[str, Any]:
    """
    Return aggregate statistics for a collection of Findings.
    """

    return FindingAggregator(
        findings
    ).statistics()


###############################################################################
# Public API
###############################################################################


__all__ = [
    "AGGREGATE_TOTAL",
    "AGGREGATE_BY_SEVERITY",
    "AGGREGATE_BY_CONFIDENCE",
    "AGGREGATE_BY_STATUS",
    "AGGREGATE_BY_CATEGORY",
    "AGGREGATE_BY_SOURCE",
    "AGGREGATE_BY_DETECTION_METHOD",
    "FindingAggregator",
    "aggregate_findings",
    "aggregate_statistics",
]
