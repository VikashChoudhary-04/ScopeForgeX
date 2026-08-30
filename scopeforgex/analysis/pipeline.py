"""
ScopeForgeX Analysis Pipeline
=============================

Central processing pipeline connecting observations produced by collectors
and native analyzers to the universal Finding system.

Architecture
------------

Collector / Native Analyzer
            |
            v
        Observation
            |
            v
     Finding Conversion
            |
            v
      Normalization
            |
            v
   Confidence Assessment
            |
            v
    Risk Classification
            |
            v
      Deduplication
            |
            v
       Correlation
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
- Processing failures are recorded rather than silently discarded.
- Dependency injection allows individual processing components to be tested
  independently.

The canonical Finding model is defined by ``reporting.models``. This module
does not maintain a second Finding representation.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from reporting.findings import FindingCollector
from reporting.models import Finding


###############################################################################
# Protocols
###############################################################################


class NormalizerProtocol(Protocol):
    """Protocol implemented by finding normalizers."""

    def normalize(
        self,
        finding: Finding,
    ) -> Finding | Mapping[str, Any] | None:
        """Normalize a finding."""
        ...


class ConfidenceProtocol(Protocol):
    """Protocol implemented by confidence processors."""

    def assess(
        self,
        finding: Finding,
    ) -> Finding | Mapping[str, Any] | None:
        """Assess finding confidence."""
        ...


class RiskProtocol(Protocol):
    """Protocol implemented by risk processors."""

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
    ) -> Iterable[Finding]:
        """Correlate findings."""
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
        Final findings produced by the pipeline.

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
        Finding conversion
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
        final findings

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
        collector: FindingCollector | None = None,
        fail_fast: bool = False,
    ) -> None:
        """
        Initialize the analysis pipeline.
        """

        self.normalizer = normalizer

        self.confidence = confidence

        self.risk = risk

        self.deduplicator = deduplicator

        self.correlator = correlator

        self.collector = (
            collector
            if collector is not None
            else FindingCollector()
        )

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

        findings = self._apply_correlation(
            findings
        )

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
        }

        return result

    def analyze(
        self,
        observations: Any,
    ) -> list[Finding]:
        """
        Process observations and return only final findings.
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
            return [observations]

        if isinstance(
            observations,
            Mapping,
        ):
            return [observations]

        if isinstance(
            observations,
            (str, bytes),
        ):
            return [observations]

        if hasattr(
            observations,
            "as_dict",
        ):
            return [observations]

        if isinstance(
            observations,
            Iterable,
        ):
            return list(
                observations
            )

        return [observations]

    ###########################################################################
    # Finding Conversion
    ###########################################################################

    def _to_finding(
        self,
        observation: Any,
    ) -> Finding:
        """
        Convert an observation into the canonical Finding model.

        Existing Finding instances are preserved.

        Mappings and observation objects are normalized through the canonical
        FindingCollector rather than relying on factory methods that do not
        exist on the universal Finding model.
        """

        if isinstance(
            observation,
            Finding,
        ):
            return observation

        if isinstance(
            observation,
            Mapping,
        ):
            findings = self.collector.add_observations(
                [observation]
            )

        elif hasattr(
            observation,
            "as_dict",
        ):
            findings = self.collector.add_observations(
                [observation]
            )

        else:
            raise TypeError(
                "Observation must be a Finding, mapping, "
                "or object exposing as_dict()."
            )

        if not findings:
            raise ValueError(
                "Observation did not produce a Finding."
            )

        return findings[-1]

    ###########################################################################
    # Processing Stages
    ###########################################################################

    def _apply_normalizer(
        self,
        finding: Finding,
    ) -> Finding:
        """
        Apply the configured normalizer.
        """

        if self.normalizer is None:
            return finding

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
        Apply risk classification when configured.
        """

        if self.risk is None:
            return finding

        processed = self.risk.classify(
            finding
        )

        return self._coerce_finding(
            processed,
            finding,
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
    ) -> list[Finding]:
        """
        Apply correlation to deduplicated findings.
        """

        if self.correlator is None:
            return findings

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
        Normalize processing-stage return values into a Finding.

        A processor may mutate the existing Finding and return None. In that
        case the original Finding is retained.
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
        Convert a processor mapping into a Finding.

        Fields omitted by a processor retain the existing finding values.
        """

        finding = fallback

        for field_name in (
            "title",
            "category",
            "severity",
            "confidence",
            "status",
            "target",
            "host",
            "port",
            "url",
            "parameter",
            "description",
            "impact",
            "remediation",
            "source_tool",
            "detection_method",
            "timestamp",
            "cwe",
            "cve",
            "references",
        ):
            if field_name not in data:
                continue

            setattr(
                finding,
                field_name,
                data[field_name],
            )

        if "evidence" in data:

            evidence = data["evidence"]

            if hasattr(
                evidence,
                "as_dict",
            ):
                finding.evidence = evidence

        if "metadata" in data:

            metadata = data["metadata"]

            if isinstance(
                metadata,
                Mapping,
            ):
                finding.metadata = dict(
                    metadata
                )

        return finding

    @staticmethod
    def _finding_from_observation(
        observation: Any,
        fallback: Finding,
    ) -> Finding:
        """
        Convert an observation object returned by a processing component.

        If the object exposes ``as_dict()``, its fields are applied to the
        existing canonical Finding.
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
    collector: FindingCollector | None = None,
    fail_fast: bool = False,
) -> AnalysisResult:
    """
    Convenience wrapper around AnalysisPipeline.
    """

    pipeline = AnalysisPipeline(
        normalizer=normalizer,
        confidence=confidence,
        risk=risk,
        deduplicator=deduplicator,
        correlator=correlator,
        collector=collector,
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
