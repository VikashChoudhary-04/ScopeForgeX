"""
ScopeForgeX Finding Deduplicator
================================

Deterministic deduplication layer for normalized ScopeForgeX findings.

Responsibilities
----------------

- Identify duplicate findings using stable semantic identity.
- Preserve the strongest available representation of a finding.
- Merge useful evidence and references from duplicate observations.
- Preserve source-tool provenance.
- Keep deduplication independent from correlation.
- Never perform network requests or external tool execution.
- Never decide whether a finding is a confirmed vulnerability.

Deduplication is intentionally separate from correlation:

    Deduplication
        = remove repeated representations of the same finding.

    Correlation
        = relate distinct findings that describe the same broader
          security condition or attack path.

Architecture
------------

Observations
    |
    v
Normalizer
    |
    v
Canonical Findings
    |
    v
FindingDeduplicator
    |
    v
Unique Findings
    |
    +--> Correlation
    +--> Risk Classification
    +--> Evidence Management
    +--> Reporting

The deduplicator operates on normalized Finding objects. It uses the
Finding semantic fingerprint as the primary identity and deliberately
ignores volatile provenance fields such as finding IDs and timestamps.

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .model import Finding
from .normalizer import FindingNormalizer


###############################################################################
# Deduplicator
###############################################################################


class FindingDeduplicator:
    """
    Deduplicate canonical ScopeForgeX findings.

    Findings are normalized before deduplication. The first occurrence
    establishes the canonical output position and later duplicate
    observations are merged into it.

    The deduplicator does not:

    - execute tools;
    - make network requests;
    - validate vulnerabilities;
    - perform correlation;
    - independently calculate risk.
    """

    name = "finding_deduplicator"

    description = (
        "Deterministically remove duplicate normalized findings while "
        "preserving useful evidence, references, metadata and provenance."
    )

    def __init__(
        self,
        normalizer: FindingNormalizer | None = None,
    ) -> None:
        """
        Initialize the deduplicator.

        Args:
            normalizer:
                Optional FindingNormalizer used when input contains
                observations or mappings instead of Finding objects.
        """

        self.normalizer = (
            normalizer
            if normalizer is not None
            else FindingNormalizer()
        )

    ###########################################################################
    # Public API
    ###########################################################################

    def deduplicate(
        self,
        findings: Iterable[Any],
    ) -> list[Finding]:
        """
        Deduplicate a collection of findings.

        The first semantic occurrence establishes the output position.
        Later duplicate observations are merged into the canonical finding.

        Args:
            findings:
                Iterable containing Findings, mappings, or supported
                observation objects.

        Returns:
            Ordered list of unique Findings.
        """

        normalized = self.normalizer.normalize_many(
            findings
        )

        unique: list[Finding] = []
        indexes: dict[str, int] = {}

        for finding in normalized:

            fingerprint = self.fingerprint(
                finding
            )

            existing_index = indexes.get(
                fingerprint
            )

            if existing_index is None:

                indexes[fingerprint] = len(
                    unique
                )

                unique.append(
                    finding
                )

                continue

            self.merge(
                unique[existing_index],
                finding,
            )

        return unique

    def deduplicate_many(
        self,
        *finding_groups: Iterable[Any],
    ) -> list[Finding]:
        """
        Deduplicate findings across multiple collections.

        This is useful when separate collectors, analyzers or workflow stages
        produce independent finding batches.
        """

        combined: list[Any] = []

        for group in finding_groups:
            combined.extend(
                group
            )

        return self.deduplicate(
            combined
        )

    def is_duplicate(
        self,
        first: Any,
        second: Any,
    ) -> bool:
        """
        Determine whether two observations represent the same finding.
        """

        first_finding = self._normalize(
            first
        )

        second_finding = self._normalize(
            second
        )

        return (
            self.fingerprint(
                first_finding
            )
            == self.fingerprint(
                second_finding
            )
        )

    ###########################################################################
    # Fingerprinting
    ###########################################################################

    @staticmethod
    def fingerprint(
        finding: Finding,
    ) -> str:
        """
        Return the semantic identity of a Finding.

        Finding.fingerprint() is the canonical identity implementation for
        normalized findings.

        The deduplicator deliberately does not use:

        - finding ID;
        - timestamp;
        - source tool;
        - detection method;
        - confidence;
        - evidence.

        Those fields may legitimately differ between observations of the
        same underlying security condition.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "fingerprint() requires a Finding."
            )

        return finding.fingerprint()

    ###########################################################################
    # Merge
    ###########################################################################

    def merge(
        self,
        primary: Finding,
        duplicate: Finding,
    ) -> Finding:
        """
        Merge a duplicate finding into the canonical finding.

        The primary finding remains the canonical object and retains its
        position in the result set.

        Merge policy:

        - preserve semantic identity;
        - preserve strongest severity;
        - preserve strongest confidence;
        - fill missing location fields;
        - preserve useful textual content;
        - merge references;
        - merge evidence;
        - preserve all source-tool provenance;
        - preserve all useful metadata;
        - do not perform independent vulnerability validation.
        """

        if not isinstance(
            primary,
            Finding,
        ):
            raise TypeError(
                "primary must be a Finding."
            )

        if not isinstance(
            duplicate,
            Finding,
        ):
            raise TypeError(
                "duplicate must be a Finding."
            )

        if primary.fingerprint() != duplicate.fingerprint():
            raise ValueError(
                "Cannot merge findings with different fingerprints."
            )

        self._merge_risk(
            primary,
            duplicate,
        )

        self._merge_locations(
            primary,
            duplicate,
        )

        self._merge_content(
            primary,
            duplicate,
        )

        self._merge_references(
            primary,
            duplicate,
        )

        self._merge_evidence(
            primary,
            duplicate,
        )

        self._merge_sources(
            primary,
            duplicate,
        )

        self._merge_metadata(
            primary,
            duplicate,
        )

        return primary

    ###########################################################################
    # Risk Merge
    ###########################################################################

    @staticmethod
    def _merge_risk(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Preserve the strongest observed severity and confidence.

        This does not independently classify the finding. It only preserves
        the strongest values already supplied by the observations.
        """

        if (
            duplicate.severity_level
            > primary.severity_level
        ):
            primary.severity = duplicate.severity

        if (
            duplicate.confidence_level
            > primary.confidence_level
        ):
            primary.confidence = duplicate.confidence

    ###########################################################################
    # Location Merge
    ###########################################################################

    @staticmethod
    def _merge_locations(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Fill missing location fields from a duplicate observation.
        """

        if not primary.target and duplicate.target:
            primary.target = duplicate.target

        if (
            primary.host is None
            and duplicate.host is not None
        ):
            primary.host = duplicate.host

        if (
            primary.port is None
            and duplicate.port is not None
        ):
            primary.port = duplicate.port

        if (
            primary.url is None
            and duplicate.url is not None
        ):
            primary.url = duplicate.url

        if (
            primary.parameter is None
            and duplicate.parameter is not None
        ):
            primary.parameter = duplicate.parameter

    ###########################################################################
    # Content Merge
    ###########################################################################

    @staticmethod
    def _merge_content(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Preserve useful textual and classification content.
        """

        if (
            not primary.description
            and duplicate.description
        ):
            primary.description = duplicate.description

        if (
            not primary.impact
            and duplicate.impact
        ):
            primary.impact = duplicate.impact

        if (
            not primary.remediation
            and duplicate.remediation
        ):
            primary.remediation = duplicate.remediation

        if (
            not primary.detection_method
            and duplicate.detection_method
        ):
            primary.detection_method = (
                duplicate.detection_method
            )

        if (
            not primary.source_tool
            and duplicate.source_tool
        ):
            primary.source_tool = (
                duplicate.source_tool
            )

        if (
            not primary.cwe
            and duplicate.cwe
        ):
            primary.cwe = duplicate.cwe

        if (
            not primary.cve
            and duplicate.cve
        ):
            primary.cve = duplicate.cve

    ###########################################################################
    # Reference Merge
    ###########################################################################

    @staticmethod
    def _merge_references(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Merge references without creating duplicates.
        """

        for reference in duplicate.references:

            primary.add_reference(
                reference
            )

    ###########################################################################
    # Evidence Merge
    ###########################################################################

    @staticmethod
    def _merge_evidence(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Preserve evidence from duplicate observations.

        Evidence is never discarded merely because the observation itself
        was deduplicated.

        If the Finding implementation supports list-based evidence,
        additional unique evidence is appended through add_evidence().
        """

        duplicate_evidence = duplicate.evidence

        if duplicate_evidence is None:
            return

        primary_evidence = primary.evidence

        if primary_evidence is None:

            primary.evidence = (
                duplicate_evidence
            )

            return

        if FindingDeduplicator._evidence_contains(
            primary_evidence,
            duplicate_evidence,
        ):
            return

        primary.add_evidence(
            duplicate_evidence
        )

    @staticmethod
    def _evidence_contains(
        existing: Any,
        candidate: Any,
    ) -> bool:
        """
        Determine whether candidate evidence is already represented.
        """

        if isinstance(
            existing,
            list,
        ):

            for item in existing:

                try:

                    if item == candidate:
                        return True

                except Exception:
                    continue

            return False

        try:
            return existing == candidate
        except Exception:
            return False

    ###########################################################################
    # Source Merge
    ###########################################################################

    @staticmethod
    def _merge_sources(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Preserve source-tool and detection-method provenance.

        The canonical source_tool field is not arbitrarily replaced by a
        later duplicate. Additional provenance is retained in metadata.
        """

        sources = FindingDeduplicator._metadata_list(
            primary.metadata.get(
                "source_tools"
            )
        )

        if primary.source_tool:
            sources.append(
                primary.source_tool
            )

        if duplicate.source_tool:
            sources.append(
                duplicate.source_tool
            )

        primary.metadata[
            "source_tools"
        ] = FindingDeduplicator._unique_strings(
            sources
        )

        methods = FindingDeduplicator._metadata_list(
            primary.metadata.get(
                "detection_methods"
            )
        )

        if primary.detection_method:
            methods.append(
                primary.detection_method
            )

        if duplicate.detection_method:
            methods.append(
                duplicate.detection_method
            )

        primary.metadata[
            "detection_methods"
        ] = FindingDeduplicator._unique_strings(
            methods
        )

    ###########################################################################
    # Metadata Merge
    ###########################################################################

    @staticmethod
    def _merge_metadata(
        primary: Finding,
        duplicate: Finding,
    ) -> None:
        """
        Merge duplicate metadata without discarding primary values.

        Scalar conflicts are represented as an ordered list so information
        from either observation is retained.
        """

        for key, value in duplicate.metadata.items():

            if key not in primary.metadata:

                primary.metadata[key] = value

                continue

            existing = primary.metadata[key]

            if existing == value:
                continue

            if isinstance(
                existing,
                list,
            ):

                values = existing

            else:

                values = [
                    existing
                ]

            if isinstance(
                value,
                list,
            ):

                candidates = value

            else:

                candidates = [
                    value
                ]

            for candidate in candidates:

                if candidate not in values:

                    values.append(
                        candidate
                    )

            primary.metadata[key] = values

    ###########################################################################
    # Normalization
    ###########################################################################

    def _normalize(
        self,
        observation: Any,
    ) -> Finding:
        """
        Normalize an arbitrary supported observation into a Finding.
        """

        if isinstance(
            observation,
            Finding,
        ):
            return observation

        return self.normalizer.normalize(
            observation
        )

    ###########################################################################
    # Metadata Helpers
    ###########################################################################

    @staticmethod
    def _metadata_list(
        value: Any,
    ) -> list[str]:
        """
        Normalize provenance metadata into a string list.
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
            (str, bytes, Mapping),
        ):

            result: list[str] = []

            for item in value:

                normalized = str(
                    item
                ).strip()

                if normalized:
                    result.append(
                        normalized
                    )

            return result

        normalized = str(
            value
        ).strip()

        return (
            [normalized]
            if normalized
            else []
        )

    @staticmethod
    def _unique_strings(
        values: Iterable[str],
    ) -> list[str]:
        """
        Return unique strings while preserving insertion order.
        """

        result: list[str] = []
        seen: set[str] = set()

        for value in values:

            normalized = str(
                value
            ).strip()

            if not normalized:
                continue

            key = normalized.lower()

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                normalized
            )

        return result


###############################################################################
# Convenience API
###############################################################################


def deduplicate_findings(
    findings: Iterable[Any],
) -> list[Finding]:
    """
    Deduplicate findings using the default FindingDeduplicator.
    """

    return FindingDeduplicator().deduplicate(
        findings
    )


def findings_are_duplicates(
    first: Any,
    second: Any,
) -> bool:
    """
    Return whether two observations have the same semantic fingerprint.
    """

    return FindingDeduplicator().is_duplicate(
        first,
        second,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "FindingDeduplicator",
    "deduplicate_findings",
    "findings_are_duplicates",
]
