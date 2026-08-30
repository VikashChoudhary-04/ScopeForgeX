"""
ScopeForgeX Finding Risk Classification
=======================================

Deterministic risk classification layer for normalized ScopeForgeX findings.

Responsibilities
----------------

- Classify normalized findings by severity.
- Preserve finding confidence independently from severity.
- Provide deterministic risk scores and risk levels.
- Support explicit severity overrides.
- Avoid treating scanner detection as vulnerability confirmation.
- Avoid network requests and external tool execution.
- Keep risk classification independent from correlation and reporting.

Risk classification is intentionally separate from confidence:

    Severity
        = potential security impact / technical seriousness.

    Confidence
        = confidence that the reported condition actually exists.

For example:

    Severity: Critical
    Confidence: Medium

is valid when a scanner detects a potentially critical issue that still
requires validation.

Architecture
------------

Normalized Finding
        |
        v
FindingRiskClassifier
        |
        +--> Severity
        +--> Risk Score
        +--> Risk Level
        +--> Confidence (preserved)
        |
        v
Deduplicated / Correlated Findings
        |
        v
Reporting

The classifier does not independently prove vulnerabilities. It only
classifies the information already represented by the Finding model.

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from scopeforgex.models.finding import Finding
from scopeforgex.runtime.enums import (
    Confidence,
    Severity,
)


###############################################################################
# Risk Levels
###############################################################################


RISK_LEVELS = (
    Severity.INFO.value,
    Severity.LOW.value,
    Severity.MEDIUM.value,
    Severity.HIGH.value,
    Severity.CRITICAL.value,
)


###############################################################################
# Severity Scores
###############################################################################


SEVERITY_SCORES: dict[str, int] = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 25,
    Severity.MEDIUM.value: 50,
    Severity.HIGH.value: 75,
    Severity.CRITICAL.value: 100,
}


###############################################################################
# Risk Result
###############################################################################


@dataclass(frozen=True, slots=True)
class RiskClassification:
    """
    Structured risk classification for a Finding.

    RiskClassification does not replace the Finding object. It represents
    the classification derived from the Finding's existing severity and
    confidence information.
    """

    severity: str

    confidence: str

    score: int

    risk_level: str

    rationale: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Serialize the risk classification."""

        return {
            "severity": self.severity,
            "confidence": self.confidence,
            "score": self.score,
            "risk_level": self.risk_level,
            "rationale": self.rationale,
        }


###############################################################################
# Risk Classifier
###############################################################################


class FindingRiskClassifier:
    """
    Deterministically classify ScopeForgeX findings.

    The classifier intentionally does not infer confirmation from scanner
    output. Confidence is preserved from the Finding and is never silently
    promoted to Confirmed.

    Severity is the primary input to risk classification.

    Confidence may affect the explanatory rationale but does not rewrite the
    finding's severity.
    """

    name = "finding_risk_classifier"

    description = (
        "Deterministically classify normalized findings by severity while "
        "preserving independent confidence."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def classify(
        self,
        finding: Finding,
    ) -> RiskClassification:
        """
        Classify a single Finding.

        Args:
            finding:
                Normalized ScopeForgeX Finding.

        Returns:
            RiskClassification.

        Raises:
            TypeError:
                If the supplied object is not a Finding.
        """

        self._validate_finding(
            finding
        )

        severity = self.normalize_severity(
            finding.severity
        )

        confidence = self.normalize_confidence(
            finding.confidence
        )

        score = self.score(
            severity
        )

        risk_level = self.risk_level(
            score
        )

        rationale = self._rationale(
            severity,
            confidence,
        )

        return RiskClassification(
            severity=severity,
            confidence=confidence,
            score=score,
            risk_level=risk_level,
            rationale=rationale,
        )

    def classify_many(
        self,
        findings: Iterable[Finding],
    ) -> list[RiskClassification]:
        """
        Classify multiple normalized findings.

        Output order matches input order.
        """

        if findings is None:
            return []

        return [
            self.classify(
                finding
            )
            for finding in findings
        ]

    def classify_and_update(
        self,
        finding: Finding,
    ) -> RiskClassification:
        """
        Classify a Finding and attach the resulting risk metadata.

        The Finding's severity and confidence remain authoritative.

        This method only adds derived risk information to metadata. It does
        not alter the Finding's confidence or promote a finding to confirmed.
        """

        classification = self.classify(
            finding
        )

        finding.metadata[
            "risk_score"
        ] = classification.score

        finding.metadata[
            "risk_level"
        ] = classification.risk_level

        finding.metadata[
            "risk_rationale"
        ] = classification.rationale

        return classification

    def classify_and_update_many(
        self,
        findings: Iterable[Finding],
    ) -> list[RiskClassification]:
        """
        Classify findings and attach risk metadata to each Finding.
        """

        if findings is None:
            return []

        classifications: list[RiskClassification] = []

        for finding in findings:
            classifications.append(
                self.classify_and_update(
                    finding
                )
            )

        return classifications

    ###########################################################################
    # Severity
    ###########################################################################

    @staticmethod
    def normalize_severity(
        severity: Any,
    ) -> str:
        """
        Normalize a severity value to the canonical ScopeForgeX severity.

        Unknown or missing values default to Informational rather than being
        treated as a high-risk finding.

        The canonical values come from runtime.enums.Severity.
        """

        if isinstance(
            severity,
            Severity,
        ):
            return severity.value

        if severity is None:
            return Severity.INFO.value

        value = str(
            severity
        ).strip()

        if not value:
            return Severity.INFO.value

        normalized = value.lower()

        aliases = {
            "info": Severity.INFO.value,
            "information": Severity.INFO.value,
            "informational": Severity.INFO.value,
            "none": Severity.INFO.value,
            "notice": Severity.INFO.value,
            "minor": Severity.LOW.value,
            "moderate": Severity.MEDIUM.value,
            "major": Severity.HIGH.value,
            "severe": Severity.CRITICAL.value,
        }

        if normalized in aliases:
            return aliases[
                normalized
            ]

        for level in Severity:
            if normalized == level.value.lower():
                return level.value

        return Severity.INFO.value

    ###########################################################################
    # Confidence
    ###########################################################################

    @staticmethod
    def normalize_confidence(
        confidence: Any,
    ) -> str:
        """
        Normalize a confidence value to the canonical ScopeForgeX level.

        Unknown or missing values default to Low.

        This conservative default prevents an unclassified scanner result from
        being presented as highly trusted.
        """

        if isinstance(
            confidence,
            Confidence,
        ):
            return confidence.value

        if confidence is None:
            return FindingRiskClassifier._confidence_low()

        value = str(
            confidence
        ).strip()

        if not value:
            return FindingRiskClassifier._confidence_low()

        normalized = value.lower()

        aliases = {
            "confirmed": "Confirmed",
            "verified": "Confirmed",
            "certain": "Confirmed",
            "high": "High",
            "medium": "Medium",
            "moderate": "Medium",
            "low": "Low",
            "informational": "Informational",
            "information": "Informational",
            "info": "Informational",
        }

        if normalized in aliases:
            return aliases[
                normalized
            ]

        for level in Confidence:
            if normalized == level.value.lower():
                return level.value

        return FindingRiskClassifier._confidence_low()

    @staticmethod
    def _confidence_low() -> str:
        """
        Return the canonical low-confidence value.

        Kept as a helper so the classifier remains independent of the exact
        enum member name used by the runtime implementation.
        """

        for level in Confidence:
            if level.value.lower() == "low":
                return level.value

        return "Low"

    ###########################################################################
    # Score
    ###########################################################################

    @staticmethod
    def score(
        severity: Any,
    ) -> int:
        """
        Return the deterministic numeric score for a severity level.
        """

        normalized = FindingRiskClassifier.normalize_severity(
            severity
        )

        return SEVERITY_SCORES[
            normalized
        ]

    @staticmethod
    def risk_level(
        score: Any,
    ) -> str:
        """
        Convert a numeric risk score into a canonical risk level.

        Boundaries:

            0       -> Informational
            1-25    -> Low
            26-50   -> Medium
            51-75   -> High
            76-100  -> Critical
        """

        try:
            numeric_score = int(
                score
            )
        except (
            TypeError,
            ValueError,
        ):
            numeric_score = 0

        numeric_score = max(
            0,
            min(
                100,
                numeric_score,
            ),
        )

        if numeric_score == 0:
            return Severity.INFO.value

        if numeric_score <= 25:
            return Severity.LOW.value

        if numeric_score <= 50:
            return Severity.MEDIUM.value

        if numeric_score <= 75:
            return Severity.HIGH.value

        return Severity.CRITICAL.value

    ###########################################################################
    # Severity Override
    ###########################################################################

    def apply_severity_override(
        self,
        finding: Finding,
        severity: str,
        *,
        reason: str = "",
    ) -> RiskClassification:
        """
        Apply an explicit analyst severity override.

        This is intentionally explicit.

        The classifier never changes severity merely because another field
        looks dangerous. An analyst or upstream trusted classification may
        deliberately override severity when justified by assessment context.

        Confidence remains unchanged.
        """

        self._validate_finding(
            finding
        )

        normalized = self.normalize_severity(
            severity
        )

        previous = self.normalize_severity(
            finding.severity
        )

        finding.severity = normalized

        finding.metadata[
            "severity_override"
        ] = {
            "previous": previous,
            "current": normalized,
            "reason": str(
                reason
            ).strip(),
        }

        return self.classify_and_update(
            finding
        )

    ###########################################################################
    # Rationale
    ###########################################################################

    @staticmethod
    def _rationale(
        severity: str,
        confidence: str,
    ) -> str:
        """
        Build a concise deterministic explanation of the classification.
        """

        if severity == Severity.INFO.value:
            return (
                "The observation is informational and does not indicate "
                "a material security risk by severity alone."
            )

        if confidence.lower() == "confirmed":
            return (
                f"The finding is classified as {severity} severity with "
                "confirmed detection confidence."
            )

        if confidence.lower() == "high":
            return (
                f"The finding is classified as {severity} severity with "
                "high detection confidence; confirmation remains distinct "
                "from severity classification."
            )

        if confidence.lower() == "medium":
            return (
                f"The finding is classified as {severity} severity with "
                "medium detection confidence and may require validation."
            )

        if confidence.lower() == "informational":
            return (
                f"The finding is classified as {severity} severity, but "
                "its detection confidence is informational."
            )

        return (
            f"The finding is classified as {severity} severity with "
            f"{confidence.lower()} detection confidence and may require "
            "further validation."
        )

    ###########################################################################
    # Validation
    ###########################################################################

    @staticmethod
    def _validate_finding(
        finding: Finding,
    ) -> None:
        """
        Validate that the classifier receives a normalized Finding.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "FindingRiskClassifier expects a Finding object."
            )


###############################################################################
# Convenience API
###############################################################################


_DEFAULT_CLASSIFIER = FindingRiskClassifier()


def classify_finding(
    finding: Finding,
) -> RiskClassification:
    """
    Classify a Finding using the default risk classifier.
    """

    return _DEFAULT_CLASSIFIER.classify(
        finding
    )


def classify_findings(
    findings: Iterable[Finding],
) -> list[RiskClassification]:
    """
    Classify findings using the default risk classifier.
    """

    return _DEFAULT_CLASSIFIER.classify_many(
        findings
    )


def classify_and_update_finding(
    finding: Finding,
) -> RiskClassification:
    """
    Classify a Finding and attach derived risk metadata.
    """

    return _DEFAULT_CLASSIFIER.classify_and_update(
        finding
    )


def risk_score(
    severity: Any,
) -> int:
    """
    Return the deterministic score for a severity level.
    """

    return FindingRiskClassifier.score(
        severity
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "RISK_LEVELS",
    "SEVERITY_SCORES",
    "RiskClassification",
    "FindingRiskClassifier",
    "classify_finding",
    "classify_findings",
    "classify_and_update_finding",
    "risk_score",
]
