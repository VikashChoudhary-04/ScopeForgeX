"""
ScopeForgeX Finding Correlator
==============================

Correlation engine for linking related canonical ScopeForgeX Findings.

The correlator operates after normalization and before final reporting. It
identifies findings that likely describe the same underlying security issue,
affected asset, endpoint, or vulnerability chain.

Responsibilities
----------------

- Correlate canonical Finding objects.
- Group related findings without modifying their identity.
- Use stable finding attributes for correlation.
- Support explicit correlation identifiers.
- Preserve all original Finding objects.
- Produce deterministic correlation groups.
- Remain independent from deduplication.
- Avoid treating correlation as vulnerability confirmation.

The correlator does not:

- Execute external tools.
- Perform network requests.
- Validate vulnerabilities.
- Delete findings.
- Replace Finding objects.
- Perform deduplication.
- Generate reports.

Architecture
------------

Canonical Findings
        |
        v
FindingCorrelator
        |
        +--> Correlation Groups
        |
        +--> Related Finding IDs
        |
        +--> Workflow / Reporting

Correlation and deduplication are intentionally separate.

Correlation answers:

    "Which findings are related?"

Deduplication answers:

    "Which findings represent the same finding and should be merged?"

v1.3.0
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .model import Finding


###############################################################################
# Constants
###############################################################################


CORRELATION_KEY_TARGET = "target"
CORRELATION_KEY_HOST = "host"
CORRELATION_KEY_URL = "url"
CORRELATION_KEY_PARAMETER = "parameter"
CORRELATION_KEY_CATEGORY = "category"
CORRELATION_KEY_CWE = "cwe"
CORRELATION_KEY_CVE = "cve"
CORRELATION_KEY_EXPLICIT = "explicit"


DEFAULT_CORRELATION_FIELDS = (
    CORRELATION_KEY_TARGET,
    CORRELATION_KEY_HOST,
    CORRELATION_KEY_URL,
    CORRELATION_KEY_PARAMETER,
    CORRELATION_KEY_CATEGORY,
)


###############################################################################
# Correlation Group
###############################################################################


@dataclass
class CorrelationGroup:
    """
    Represent a deterministic group of related Findings.

    A group contains references to the original Finding objects rather than
    copies. This preserves object identity for downstream workflow stages.
    """

    group_id: str
    finding_ids: list[str] = field(default_factory=list)
    reason: str = ""
    key: str = ""

    @property
    def size(self) -> int:
        """Return the number of Findings in the group."""

        return len(self.finding_ids)

    def add(
        self,
        finding: Finding,
    ) -> None:
        """
        Add a Finding identifier if it is not already present.
        """

        if finding.finding_id not in self.finding_ids:
            self.finding_ids.append(
                finding.finding_id
            )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the correlation group.
        """

        return {
            "group_id": self.group_id,
            "finding_ids": list(
                self.finding_ids
            ),
            "reason": self.reason,
            "key": self.key,
            "size": self.size,
        }


###############################################################################
# Finding Correlator
###############################################################################


class FindingCorrelator:
    """
    Correlate canonical ScopeForgeX Findings.

    Correlation is deliberately conservative. Findings are related only when
    they share sufficiently meaningful attributes or an explicit correlation
    identifier.

    No Finding is altered during correlation.
    """

    name = "finding_correlator"

    description = (
        "Correlate related ScopeForgeX findings without deduplicating or "
        "modifying the original findings."
    )

    def __init__(
        self,
        *,
        fields: Iterable[str] = DEFAULT_CORRELATION_FIELDS,
        minimum_matches: int = 2,
    ) -> None:
        """
        Initialize the correlator.

        Args:
            fields:
                Finding attributes considered for correlation.

            minimum_matches:
                Minimum number of meaningful matching fields required for
                ordinary correlation.

        Raises:
            ValueError:
                If minimum_matches is less than one or no valid fields are
                supplied.
        """

        if minimum_matches < 1:
            raise ValueError(
                "minimum_matches must be greater than or equal to 1."
            )

        normalized_fields = []

        for field_name in fields:
            field_name = str(
                field_name
            ).strip()

            if (
                field_name
                and field_name not in normalized_fields
            ):
                normalized_fields.append(
                    field_name
                )

        if not normalized_fields:
            raise ValueError(
                "At least one correlation field is required."
            )

        self.fields = tuple(
            normalized_fields
        )

        self.minimum_matches = minimum_matches

    ###########################################################################
    # Public API
    ###########################################################################

    def correlate(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate a collection of Findings.

        Only groups containing two or more Findings are returned.

        The returned order is deterministic and follows the first occurrence
        of each correlation group in the input.
        """

        normalized = self._normalize_findings(
            findings
        )

        if len(normalized) < 2:
            return []

        groups: list[CorrelationGroup] = []
        assigned: set[str] = set()

        # Explicit correlation identifiers always take precedence.
        explicit_groups = self._explicit_groups(
            normalized
        )

        for group in explicit_groups:
            groups.append(
                group
            )

            assigned.update(
                group.finding_ids
            )

        remaining = [
            finding
            for finding in normalized
            if finding.finding_id not in assigned
        ]

        ordinary_groups = self._ordinary_groups(
            remaining
        )

        groups.extend(
            ordinary_groups
        )

        return groups

    def correlate_many(
        self,
        findings: Iterable[Finding],
    ) -> list[list[Finding]]:
        """
        Return correlated Findings as object groups.

        Original Finding objects are preserved.
        """

        normalized = self._normalize_findings(
            findings
        )

        lookup = {
            finding.finding_id: finding
            for finding in normalized
        }

        groups = self.correlate(
            normalized
        )

        return [
            [
                lookup[finding_id]
                for finding_id in group.finding_ids
                if finding_id in lookup
            ]
            for group in groups
        ]

    def related(
        self,
        finding: Finding,
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Find Findings correlated with one supplied Finding.

        The supplied Finding itself is excluded from the result.
        """

        self._require_finding(
            finding
        )

        normalized = self._normalize_findings(
            findings
        )

        if all(
            item.finding_id != finding.finding_id
            for item in normalized
        ):
            normalized.append(
                finding
            )

        groups = self.correlate(
            normalized
        )

        related_ids: set[str] = set()

        for group in groups:
            if finding.finding_id in group.finding_ids:
                related_ids.update(
                    group.finding_ids
                )

        related_ids.discard(
            finding.finding_id
        )

        lookup = {
            item.finding_id: item
            for item in normalized
        }

        return [
            lookup[finding_id]
            for finding_id in related_ids
            if finding_id in lookup
        ]

    ###########################################################################
    # Explicit Correlation
    ###########################################################################

    def _explicit_groups(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Build groups using explicit correlation metadata.

        Supported metadata keys:

            correlation_id
            correlation_key

        Explicit correlation identifiers are authoritative for correlation,
        but do not imply that the findings are duplicates or confirmed.
        """

        buckets: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            metadata = self._metadata(
                finding
            )

            explicit = (
                metadata.get(
                    "correlation_id"
                )
                or metadata.get(
                    "correlation_key"
                )
            )

            if explicit is None:
                continue

            explicit = self._text(
                explicit
            )

            if explicit:
                buckets[
                    explicit
                ].append(
                    finding
                )

        groups: list[CorrelationGroup] = []

        for key, members in buckets.items():

            if len(members) < 2:
                continue

            group = CorrelationGroup(
                group_id=self._group_id(
                    "explicit",
                    key,
                ),
                reason="explicit correlation identifier",
                key=key,
            )

            for finding in members:
                group.add(
                    finding
                )

            groups.append(
                group
            )

        return groups

    ###########################################################################
    # Ordinary Correlation
    ###########################################################################

    def _ordinary_groups(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate Findings using configured attributes.

        Findings are compared pairwise. A connected-component approach is
        used so that related findings remain in one group even when different
        pairs match on different fields.
        """

        if len(findings) < 2:
            return []

        adjacency: dict[str, set[str]] = {
            finding.finding_id: set()
            for finding in findings
        }

        reasons: dict[
            tuple[str, str],
            list[str],
        ] = {}

        for index, left in enumerate(
            findings
        ):
            for right in findings[
                index + 1:
            ]:
                matches = self._matching_fields(
                    left,
                    right,
                )

                if len(matches) < self.minimum_matches:
                    continue

                left_id = left.finding_id
                right_id = right.finding_id

                adjacency[
                    left_id
                ].add(
                    right_id
                )

                adjacency[
                    right_id
                ].add(
                    left_id
                )

                pair = tuple(
                    sorted(
                        (
                            left_id,
                            right_id,
                        )
                    )
                )

                reasons[
                    pair
                ] = matches

        return self._build_components(
            findings,
            adjacency,
            reasons,
        )

    def _build_components(
        self,
        findings: list[Finding],
        adjacency: Mapping[str, set[str]],
        reasons: Mapping[
            tuple[str, str],
            list[str],
        ],
    ) -> list[CorrelationGroup]:
        """
        Convert pairwise relationships into deterministic groups.
        """

        lookup = {
            finding.finding_id: finding
            for finding in findings
        }

        visited: set[str] = set()
        groups: list[CorrelationGroup] = []

        for finding in findings:

            root_id = finding.finding_id

            if root_id in visited:
                continue

            if not adjacency.get(
                root_id
            ):
                visited.add(
                    root_id
                )
                continue

            stack = [
                root_id
            ]

            component: list[str] = []

            while stack:
                current = stack.pop()

                if current in visited:
                    continue

                visited.add(
                    current
                )

                component.append(
                    current
                )

                stack.extend(
                    neighbor
                    for neighbor in adjacency.get(
                        current,
                        set(),
                    )
                    if neighbor not in visited
                )

            if len(component) < 2:
                continue

            component.sort(
                key=lambda item: self._finding_order(
                    item,
                    findings,
                )
            )

            matching_fields: list[str] = []

            for index, left_id in enumerate(
                component
            ):
                for right_id in component[
                    index + 1:
                ]:
                    pair = tuple(
                        sorted(
                            (
                                left_id,
                                right_id,
                            )
                        )
                    )

                    for field_name in reasons.get(
                        pair,
                        [],
                    ):
                        if (
                            field_name
                            not in matching_fields
                        ):
                            matching_fields.append(
                                field_name
                            )

            key = self._component_key(
                component
            )

            group = CorrelationGroup(
                group_id=self._group_id(
                    "related",
                    key,
                ),
                reason=(
                    "shared finding attributes: "
                    + ", ".join(
                        matching_fields
                    )
                ),
                key=key,
            )

            for finding_id in component:
                group.add(
                    lookup[finding_id]
                )

            groups.append(
                group
            )

        return groups

    ###########################################################################
    # Matching
    ###########################################################################

    def _matching_fields(
        self,
        left: Finding,
        right: Finding,
    ) -> list[str]:
        """
        Return configured fields whose values meaningfully match.
        """

        matches: list[str] = []

        for field_name in self.fields:

            left_value = self._field_value(
                left,
                field_name,
            )

            right_value = self._field_value(
                right,
                field_name,
            )

            if not self._meaningful(
                left_value
            ):
                continue

            if not self._meaningful(
                right_value
            ):
                continue

            if self._values_equal(
                left_value,
                right_value,
            ):
                matches.append(
                    field_name
                )

        return matches

    @staticmethod
    def _field_value(
        finding: Finding,
        field_name: str,
    ) -> Any:
        """
        Read a correlation field from a Finding.
        """

        if field_name == CORRELATION_KEY_EXPLICIT:
            metadata = FindingCorrelator._metadata(
                finding
            )

            return (
                metadata.get(
                    "correlation_id"
                )
                or metadata.get(
                    "correlation_key"
                )
            )

        if hasattr(
            finding,
            field_name,
        ):
            return getattr(
                finding,
                field_name,
            )

        metadata = FindingCorrelator._metadata(
            finding
        )

        return metadata.get(
            field_name
        )

    @staticmethod
    def _values_equal(
        left: Any,
        right: Any,
    ) -> bool:
        """
        Compare correlation values conservatively.
        """

        if isinstance(
            left,
            str,
        ) and isinstance(
            right,
            str,
        ):
            return (
                left.strip().lower()
                == right.strip().lower()
            )

        return left == right

    @staticmethod
    def _meaningful(
        value: Any,
    ) -> bool:
        """
        Determine whether a value is useful for correlation.
        """

        if value is None:
            return False

        if isinstance(
            value,
            str,
        ):
            return bool(
                value.strip()
            )

        if isinstance(
            value,
            (list, tuple, set, dict),
        ):
            return bool(
                value
            )

        return True

    ###########################################################################
    # Input Validation
    ###########################################################################

    @staticmethod
    def _normalize_findings(
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Validate and normalize an iterable of Findings.

        Duplicate object identifiers are retained only once. The first
        occurrence determines ordering.
        """

        if findings is None:
            return []

        if isinstance(
            findings,
            Finding,
        ):
            findings = [
                findings
            ]

        result: list[Finding] = []
        seen: set[str] = set()

        for finding in findings:

            FindingCorrelator._require_finding(
                finding
            )

            finding_id = finding.finding_id

            if finding_id in seen:
                continue

            seen.add(
                finding_id
            )

            result.append(
                finding
            )

        return result

    @staticmethod
    def _require_finding(
        finding: Finding,
    ) -> None:
        """
        Require the canonical Finding model.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "FindingCorrelator requires canonical "
                "scopeforgex.models.finding.Finding objects."
            )

    ###########################################################################
    # Utility Helpers
    ###########################################################################

    @staticmethod
    def _metadata(
        finding: Finding,
    ) -> Mapping[str, Any]:
        """
        Safely obtain Finding metadata.
        """

        metadata = getattr(
            finding,
            "metadata",
            None,
        )

        if isinstance(
            metadata,
            Mapping,
        ):
            return metadata

        return {}

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

    @staticmethod
    def _component_key(
        finding_ids: Iterable[str],
    ) -> str:
        """
        Build a deterministic component key.
        """

        return "|".join(
            sorted(
                finding_ids
            )
        )

    @staticmethod
    def _group_id(
        prefix: str,
        key: str,
    ) -> str:
        """
        Build a deterministic correlation group identifier.

        A cryptographic hash is intentionally avoided so the identifier
        remains readable and stable.
        """

        import hashlib

        digest = hashlib.sha256(
            key.encode(
                "utf-8"
            )
        ).hexdigest()[:12]

        return (
            f"SF-CORR-{prefix.upper()}-{digest}"
        )

    @staticmethod
    def _finding_order(
        finding_id: str,
        findings: list[Finding],
    ) -> int:
        """
        Return the original input position of a Finding.
        """

        for index, finding in enumerate(
            findings
        ):
            if finding.finding_id == finding_id:
                return index

        return len(
            findings
        )

    ###########################################################################
    # Serialization
    ###########################################################################

    @staticmethod
    def serialize(
        groups: Iterable[CorrelationGroup],
    ) -> list[dict[str, Any]]:
        """
        Serialize correlation groups into dictionaries.
        """

        if groups is None:
            return []

        result: list[dict[str, Any]] = []

        for group in groups:

            if not isinstance(
                group,
                CorrelationGroup,
            ):
                raise TypeError(
                    "serialize() expects CorrelationGroup objects."
                )

            result.append(
                group.as_dict()
            )

        return result


###############################################################################
# Convenience API
###############################################################################


def correlate_findings(
    findings: Iterable[Finding],
    *,
    fields: Iterable[str] = DEFAULT_CORRELATION_FIELDS,
    minimum_matches: int = 2,
) -> list[CorrelationGroup]:
    """
    Correlate Findings using a temporary FindingCorrelator.
    """

    return FindingCorrelator(
        fields=fields,
        minimum_matches=minimum_matches,
    ).correlate(
        findings
    )


def find_related(
    finding: Finding,
    findings: Iterable[Finding],
    *,
    fields: Iterable[str] = DEFAULT_CORRELATION_FIELDS,
    minimum_matches: int = 2,
) -> list[Finding]:
    """
    Find Findings related to one supplied Finding.
    """

    return FindingCorrelator(
        fields=fields,
        minimum_matches=minimum_matches,
    ).related(
        finding,
        findings,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "CORRELATION_KEY_TARGET",
    "CORRELATION_KEY_HOST",
    "CORRELATION_KEY_URL",
    "CORRELATION_KEY_PARAMETER",
    "CORRELATION_KEY_CATEGORY",
    "CORRELATION_KEY_CWE",
    "CORRELATION_KEY_CVE",
    "CORRELATION_KEY_EXPLICIT",
    "DEFAULT_CORRELATION_FIELDS",
    "CorrelationGroup",
    "FindingCorrelator",
    "correlate_findings",
    "find_related",
    ]
