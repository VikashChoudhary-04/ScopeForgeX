"""
ScopeForgeX Analysis Pipeline
=============================

Central processing pipeline connecting observations produced by collectors
and native analyzers to the universal ScopeForgeX Finding system.

Architecture
------------

Collector / Native Analyzer
            |
            v
        Observation
            |
            v
        Normalization
            |
            v
          Finding
            |
            +--> Confidence Assessment
            |
            +--> Risk Classification
            |
            v
       Deduplication
            |
            v
        Unique Findings
            |
            v
         Correlation
            |
            +--> Correlation Groups
            |
            v
      Final Findings

Responsibilities
----------------

This module orchestrates finding processing. It does not:

- Execute external tools
- Construct tool commands
- Parse tool-specific output
- Implement individual security checks
- Generate reports
- Persist evidence

Those responsibilities belong to their respective layers.

Design Principles
-----------------

- One canonical Finding representation.
- Collectors and analyzers remain independent.
- Processing stages are explicit and independently replaceable.
- Empty or invalid observations do not terminate the complete pipeline.
- Original source information remains attached to findings.
- Deduplication occurs before correlation.
- Correlation never replaces the Finding collection with correlation groups.
- Processing failures are recorded rather than silently discarded.
- Dependency injection allows individual processing components to be tested
  independently.
- The canonical Finding model is ``scopeforgex.findings.model.Finding``.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from scopeforgex.findings.model import Finding
from scopeforgex.findings.normalizer import FindingNormalizer


###############################################################################
# Protocols
###############################################################################


class NormalizerProtocol(Protocol):
    """Protocol implemented by finding normalizers."""

    def normalize(
        self,
        observation: Any,
    ) -> Finding:
        """Normalize one observation into a canonical Finding."""
        ...


class ConfidenceProtocol(Protocol):
    """Protocol implemented by finding confidence processors."""

    def assess(
        self,
        finding: Finding,
    ) -> Finding | Mapping[str, Any] | None:
        """Assess finding confidence."""
        ...


class RiskProtocol(Protocol):
    """Protocol implemented by finding risk processors."""

    def classify(
        self,
        finding: Finding,
    ) -> Finding | Mapping[str, Any] | None:
        """Classify finding risk."""
        ...


class DeduplicatorProtocol(Protocol):
    """Protocol implemented by finding deduplicators."""

    def deduplicate(
        self,
        findings: Iterable[Finding],
    ) -> Iterable[Finding]:
        """Deduplicate findings."""
        ...


class CorrelatorProtocol(Protocol):
    """Protocol implemented by finding correlators."""

    def correlate(
        self,
        findings: Iterable[Finding],
    ) -> Iterable[Any]:
        """
        Correlate findings.

        The canonical correlator returns correlation-group objects rather
        than replacing the original Finding collection.
        """
        ...


###############################################################################
# Pipeline Result
###############################################################################


@dataclass(slots=True)
class AnalysisResult:
    """
    Result returned by the analysis pipeline.

    Attributes
    ----------
    findings:
        Final deduplicated Finding objects.

    correlation_groups:
        Correlation groups generated from the final deduplicated findings.

    input_count:
        Number of observations supplied to the pipeline.

    finding_count:
        Number of findings produced before deduplication and correlation.

    duplicate_count:
        Number of duplicate findings removed.

    error_count:
        Number of observations that could not be processed.

    errors:
        Structured processing errors.

    metadata:
        Additional pipeline information.
    """

    findings: list[Finding] = field(
        default_factory=list,
    )

    correlation_groups: list[Any] = field(
        default_factory=list,
    )

    input_count: int = 0

    finding_count: int = 0

    duplicate_count: int = 0

    error_count: int = 0

    errors: list[dict[str, Any]] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def success(
        self,
    ) -> bool:
        """Return True when no processing errors occurred."""

        return self.error_count == 0

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """Serialize the analysis result."""

        return {
            "findings": [
                finding.as_dict()
                for finding in self.findings
            ],
            "correlation_groups": [
                (
                    group.as_dict()
                    if hasattr(
                        group,
                        "as_dict",
                    )
                    else group
                )
                for group in self.correlation_groups
            ],
            "input_count": self.input_count,
            "finding_count": self.finding_count,
            "duplicate_count": self.duplicate_count,
            "error_count": self.error_count,
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
        }


###############################################################################
# Pipeline
###############################################################################


class AnalysisPipeline:
    """
    Universal ScopeForgeX finding-analysis pipeline.

    Processing order:

        observation
            ↓
        normalization
            ↓
        confidence assessment
            ↓
        risk classification
            ↓
        deduplication
            ↓
        correlation
            ↓
        final findings + correlation groups

    Every processing component is optional.
    """

    def __init__(
        self,
        *,
        normalizer: NormalizerProtocol | None = None,
        confidence: ConfidenceProtocol | None = None,
        risk: RiskProtocol | None = None,
        deduplicator: DeduplicatorProtocol | None = None,
        correlator: CorrelatorProtocol | None = None,
        fail_fast: bool = False,
    ) -> None:
        """
        Initialize the analysis pipeline.

        When no normalizer is supplied, the canonical
        ``FindingNormalizer`` is used.
        """

        self.normalizer = (
            normalizer
            if normalizer is not None
            else FindingNormalizer()
        )

        self.confidence = confidence

        self.risk = risk

        self.deduplicator = deduplicator

        self.correlator = correlator

        self.fail_fast = fail_fast

    ###########################################################################
    # Public API
    ###########################################################################

    def process(
        self,
        observations: Any,
    ) -> AnalysisResult:
        """
        Process observations through the complete analysis pipeline.
        """

        normalized_inputs = self._coerce_inputs(
            observations
        )

        result = AnalysisResult(
            input_count=len(
                normalized_inputs
            )
        )

        findings: list[Finding] = []

        for index, observation in enumerate(
            normalized_inputs
        ):
            try:
                finding = self._to_finding(
                    observation
                )

                finding = self._apply_normalizer(
                    finding
                )

                finding = self._apply_confidence(
                    finding
                )

                finding = self._apply_risk(
                    finding
                )

                findings.append(
                    finding
                )

            except Exception as exc:
                result.error_count += 1

                result.errors.append(
                    {
                        "index": index,
                        "type": type(exc).__name__,
                        "message": str(exc),
                    }
                )

                if self.fail_fast:
                    raise

        result.finding_count = len(
            findings
        )

        findings, duplicate_count = (
            self._apply_deduplication(
                findings
            )
        )

        result.duplicate_count = (
            duplicate_count
        )

        result.correlation_groups = (
            self._apply_correlation(
                findings
            )
        )

        # Correlation describes relationships between findings. It does not
        # replace the deduplicated Finding collection.
        result.findings = list(
            findings
        )

        result.metadata = {
            "normalizer_enabled": (
                self.normalizer is not None
            ),
            "confidence_enabled": (
                self.confidence is not None
            ),
            "risk_enabled": (
                self.risk is not None
            ),
            "deduplication_enabled": (
                self.deduplicator is not None
            ),
            "correlation_enabled": (
                self.correlator is not None
            ),
            "canonical_finding_model": (
                "scopeforgex.findings.model.Finding"
            ),
            "correlation_group_count": (
                len(
                    result.correlation_groups
                )
            ),
        }

        return result

    def analyze(
        self,
        observations: Any,
    ) -> list[Finding]:
        """
        Process observations and return only final findings.

        Correlation groups remain available through ``process()``.
        """

        return self.process(
            observations
        ).findings

    ###########################################################################
    # Input Handling
    ###########################################################################

    @staticmethod
    def _coerce_inputs(
        observations: Any,
    ) -> list[Any]:
        """
        Convert supported input forms into a list.

        Strings and mappings are treated as single observations.
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
                observations
            ]

        if isinstance(
            observations,
            (str, bytes),
        ):
            return [
                observations
            ]

        if hasattr(
            observations,
            "as_dict",
        ):
            return [
                observations
            ]

        if isinstance(
            observations,
            Iterable,
        ):
            return list(
                observations
            )

        return [
            observations
        ]

    ###########################################################################
    # Finding Conversion
    ###########################################################################

    def _to_finding(
        self,
        observation: Any,
    ) -> Finding:
        """
        Convert an observation into the canonical ScopeForgeX Finding model.

        Existing canonical Finding instances are preserved.

        Mappings and supported observation objects are normalized through the
        canonical FindingNormalizer. No second Finding representation is
        created.
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
    # Processing Stages
    ###########################################################################

    def _apply_normalizer(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Apply the configured normalizer.

        The normalizer is already guaranteed to exist by construction.
        """

        processed = self.normalizer.normalize(
            finding
        )

        return self._coerce_finding(
            processed,
            finding,
        )

    def _apply_confidence(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Apply confidence processing when configured.
        """

        if self.confidence is None:
            return finding

        processed = self.confidence.assess(
            finding
        )

        return self._coerce_finding(
            processed,
            finding,
        )

    def _apply_risk(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Apply risk processing when configured.

        A risk classifier may return a Finding, a mapping, or None.
        """

        if self.risk is None:
            return finding

        processed = self.risk.classify(
            finding
        )

        # The canonical FindingRiskClassifier currently returns a
        # RiskClassification object. If the classifier attaches its result
        # directly to the Finding and returns None, retain the Finding.
        if processed is None:
            return finding

        if isinstance(
            processed,
            Finding,
        ):
            return processed

        if isinstance(
            processed,
            Mapping,
        ):
            return self._coerce_finding(
                processed,
                finding,
            )

        if hasattr(
            processed,
            "as_dict",
        ):
            classification = processed.as_dict()

            if isinstance(
                classification,
                Mapping,
            ):
                metadata = dict(
                    finding.metadata
                )

                metadata[
                    "risk_classification"
                ] = dict(
                    classification
                )

                finding.metadata = metadata

            return finding

        raise TypeError(
            "Risk processor must return a Finding, mapping, "
            "object exposing as_dict(), or None."
        )

    ###########################################################################
    # Deduplication
    ###########################################################################

    def _apply_deduplication(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], int]:
        """
        Apply deduplication and calculate removed findings.
        """

        if self.deduplicator is None:
            return findings, 0

        before = len(
            findings
        )

        processed = self.deduplicator.deduplicate(
            findings
        )

        final = list(
            processed
        )

        removed = max(
            0,
            before - len(final),
        )

        return final, removed

    ###########################################################################
    # Correlation
    ###########################################################################

    def _apply_correlation(
        self,
        findings: list[Finding],
    ) -> list[Any]:
        """
        Correlate deduplicated findings.

        Correlation groups are returned separately. The Finding collection is
        never replaced by CorrelationGroup objects.
        """

        if self.correlator is None:
            return []

        processed = self.correlator.correlate(
            findings
        )

        return list(
            processed
        )

    ###########################################################################
    # Return-Value Normalization
    ###########################################################################

    @staticmethod
    def _coerce_finding(
        value: Any,
        fallback: Finding,
    ) -> Finding:
        """
        Normalize processing-stage return values into the canonical Finding.

        A processor may mutate the existing Finding and return None. In that
        case the original Finding is retained.

        Mapping and observation returns are normalized against the canonical
        ScopeForgeX Finding model.
        """

        if value is None:
            return fallback

        if isinstance(
            value,
            Finding,
        ):
            return value

        if isinstance(
            value,
            Mapping,
        ):
            return AnalysisPipeline._finding_from_mapping(
                value,
                fallback,
            )

        if hasattr(
            value,
            "as_dict",
        ):
            return AnalysisPipeline._finding_from_observation(
                value,
                fallback,
            )

        raise TypeError(
            "Analysis component must return a Finding, "
            "mapping, observation, or None."
        )

    ###########################################################################
    # Canonical Finding Conversion Helpers
    ###########################################################################

    @staticmethod
    def _finding_from_mapping(
        data: Mapping[str, Any],
        fallback: Finding,
    ) -> Finding:
        """
        Apply supported mapping fields to an existing canonical Finding.

        Fields omitted by a processor retain existing values.
        """

        finding = fallback

        field_names = (
            "finding_id",
            "title",
            "category",
            "severity",
            "confidence",
            "target",
            "host",
            "port",
            "url",
            "parameter",
            "description",
            "evidence",
            "source_tool",
            "detection_method",
            "timestamp",
            "cwe",
            "cve",
            "references",
            "impact",
            "remediation",
            "status",
            "metadata",
        )

        for field_name in field_names:

            if field_name not in data:
                continue

            value = data[
                field_name
            ]

            if field_name == "metadata":

                if isinstance(
                    value,
                    Mapping,
                ):
                    finding.metadata = dict(
                        value
                    )

                continue

            if field_name == "evidence":

                if value is not None:
                    finding.evidence = value

                continue

            if hasattr(
                finding,
                field_name,
            ):

                setattr(
                    finding,
                    field_name,
                    value,
                )

        return finding

    @staticmethod
    def _finding_from_observation(
        observation: Any,
        fallback: Finding,
    ) -> Finding:
        """
        Convert an observation-like object returned by a processor.

        Its serialized fields are applied to the existing canonical Finding.
        """

        data = observation.as_dict()

        if not isinstance(
            data,
            Mapping,
        ):
            raise TypeError(
                "Observation as_dict() must return a mapping."
            )

        return AnalysisPipeline._finding_from_mapping(
            data,
            fallback,
        )


###############################################################################
# Convenience Function
###############################################################################


def analyze(
    observations: Any,
    *,
    normalizer: NormalizerProtocol | None = None,
    confidence: ConfidenceProtocol | None = None,
    risk: RiskProtocol | None = None,
    deduplicator: DeduplicatorProtocol | None = None,
    correlator: CorrelatorProtocol | None = None,
    fail_fast: bool = False,
) -> AnalysisResult:
    """
    Convenience wrapper around :class:`AnalysisPipeline`.
    """

    pipeline = AnalysisPipeline(
        normalizer=normalizer,
        confidence=confidence,
        risk=risk,
        deduplicator=deduplicator,
        correlator=correlator,
        fail_fast=fail_fast,
    )

    return pipeline.process(
        observations
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "AnalysisPipeline",
    "AnalysisResult",
    "NormalizerProtocol",
    "ConfidenceProtocol",
    "RiskProtocol",
    "DeduplicatorProtocol",
    "CorrelatorProtocol",
    "analyze",
]
