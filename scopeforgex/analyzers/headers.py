"""
ScopeForgeX HTTP Security Headers Analyzer
===========================================

ScopeForgeX-native analyzer for deterministic HTTP security-header analysis.

The analyzer consumes HTTP response evidence already collected by the
ScopeForgeX workflow. It does not perform network requests.

Headers analyzed:

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Finding types:

- MISSING_SECURITY_HEADER
- WEAK_SECURITY_HEADER
- SECURITY_HEADER_MISCONFIGURATION

Detection is not confirmation of a vulnerability. Findings represent
configuration observations derived from collected HTTP evidence.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


###############################################################################
# Constants
###############################################################################


MISSING_SECURITY_HEADER = "MISSING_SECURITY_HEADER"
WEAK_SECURITY_HEADER = "WEAK_SECURITY_HEADER"
SECURITY_HEADER_MISCONFIGURATION = "SECURITY_HEADER_MISCONFIGURATION"


SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


###############################################################################
# Observation Model
###############################################################################


@dataclass(slots=True)
class HeaderObservation:
    """
    Normalized HTTP security-header observation.

    The observation describes a missing, weak or misconfigured security
    header found in already-collected HTTP response evidence.
    """

    finding_type: str
    title: str
    severity: str
    confidence: str
    target: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source_tool: str = "scopeforgex"
    detection_method: str = "HTTP Security Header Analyzer"
    remediation: str = ""
    category: str = "http_security_headers"

    def as_dict(self) -> dict[str, Any]:
        """Serialize the observation into a stable dictionary."""

        return {
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "description": self.description,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "remediation": self.remediation,
            "category": self.category,
        }


###############################################################################
# Analyzer
###############################################################################


class HeadersAnalyzer:
    """
    Analyze collected HTTP response headers.

    Supported evidence forms include:

        {
            "target": "https://example.com",
            "headers": {
                "Content-Security-Policy": "...",
                "Strict-Transport-Security": "...",
            },
        }

    Multiple response records are also supported:

        {
            "responses": [
                {
                    "url": "https://example.com",
                    "headers": {
                        "Content-Security-Policy": "...",
                    },
                },
            ],
        }

    The analyzer only inspects supplied evidence.
    """

    name = "headers"

    description = (
        "Analyze collected HTTP response headers for missing, weak or "
        "misconfigured security headers."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[HeaderObservation]:
        """
        Analyze collected HTTP security-header evidence.

        Returns:
            A list of normalized HeaderObservation objects.
        """

        observations: list[HeaderObservation] = []
        seen: set[tuple[str, str, str]] = set()

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        records = self._extract_records(evidence)

        if not records:
            records = [
                evidence,
            ]

        for record in records:
            response_target = str(
                record.get(
                    "url",
                    record.get(
                        "target",
                        target,
                    ),
                )
            ).strip()

            headers = self._extract_headers(record)

            if not headers:
                continue

            normalized_headers = self._normalize_headers(headers)

            for header_name in SECURITY_HEADERS:
                header_value = normalized_headers.get(
                    header_name.lower()
                )

                if header_value is None:
                    observation = self._missing_header(
                        target=response_target,
                        header_name=header_name,
                    )
                else:
                    observation = self._evaluate_header(
                        target=response_target,
                        header_name=header_name,
                        value=header_value,
                    )

                if observation is None:
                    continue

                key = (
                    observation.finding_type,
                    response_target,
                    header_name,
                )

                if key in seen:
                    continue

                seen.add(key)
                observations.append(observation)

        return observations

    # ------------------------------------------------------------------
    # Evidence Extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_records(
        evidence: Mapping[str, Any],
    ) -> list[Mapping[str, Any]]:
        """
        Extract HTTP response records from common evidence fields.
        """

        records: list[Mapping[str, Any]] = []

        for key in (
            "responses",
            "http_responses",
            "documents",
        ):
            value = evidence.get(key)

            if value is None:
                continue

            if isinstance(value, Mapping):
                records.append(value)
                continue

            if isinstance(value, Iterable) and not isinstance(
                value,
                (str, bytes),
            ):
                for item in value:
                    if isinstance(item, Mapping):
                        records.append(item)

        return records

    @staticmethod
    def _extract_headers(
        record: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """
        Extract response headers from a collected record.
        """

        headers = record.get("headers")

        if isinstance(headers, Mapping):
            return headers

        response_headers = record.get("response_headers")

        if isinstance(response_headers, Mapping):
            return response_headers

        response = record.get("response")

        if isinstance(response, Mapping):
            nested_headers = response.get("headers")

            if isinstance(nested_headers, Mapping):
                return nested_headers

        return {}

    @staticmethod
    def _normalize_headers(
        headers: Mapping[str, Any],
    ) -> dict[str, str]:
        """
        Normalize header names while preserving their values.
        """

        normalized: dict[str, str] = {}

        for name, value in headers.items():
            header_name = str(name).strip().lower()

            if not header_name:
                continue

            if isinstance(value, (list, tuple)):
                header_value = ", ".join(
                    str(item).strip()
                    for item in value
                )
            else:
                header_value = str(value).strip()

            normalized[header_name] = header_value

        return normalized

    # ------------------------------------------------------------------
    # Header Evaluation
    # ------------------------------------------------------------------

    def _evaluate_header(
        self,
        target: str,
        header_name: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate one supported security header.
        """

        if header_name == "Content-Security-Policy":
            return self._evaluate_csp(
                target,
                value,
            )

        if header_name == "Strict-Transport-Security":
            return self._evaluate_hsts(
                target,
                value,
            )

        if header_name == "X-Frame-Options":
            return self._evaluate_x_frame_options(
                target,
                value,
            )

        if header_name == "X-Content-Type-Options":
            return self._evaluate_x_content_type_options(
                target,
                value,
            )

        if header_name == "Referrer-Policy":
            return self._evaluate_referrer_policy(
                target,
                value,
            )

        if header_name == "Permissions-Policy":
            return self._evaluate_permissions_policy(
                target,
                value,
            )

        return None

    # ------------------------------------------------------------------
    # Missing Headers
    # ------------------------------------------------------------------

    @staticmethod
    def _missing_header(
        target: str,
        header_name: str,
    ) -> HeaderObservation:
        """
        Build an observation for a missing security header.
        """

        return HeaderObservation(
            finding_type=MISSING_SECURITY_HEADER,
            title=f"Missing Security Header: {header_name}",
            severity="Low",
            confidence="High",
            target=target,
            description=(
                f"The HTTP response does not contain the recommended "
                f"{header_name} security header."
            ),
            evidence={
                "header": header_name,
                "value": None,
            },
            remediation=(
                f"Review the {header_name} header and configure an "
                "appropriate value for the application."
            ),
        )

    # ------------------------------------------------------------------
    # Content-Security-Policy
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_csp(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate basic deterministic CSP weaknesses.

        The analyzer intentionally limits itself to clearly identifiable
        configuration observations and does not attempt to prove exploitability.
        """

        normalized = value.lower()

        if not value.strip():
            return HeaderObservation(
                finding_type=SECURITY_HEADER_MISCONFIGURATION,
                title="Misconfigured Content-Security-Policy",
                severity="Medium",
                confidence="High",
                target=target,
                description=(
                    "The Content-Security-Policy header is present but "
                    "contains no effective policy value."
                ),
                evidence={
                    "header": "Content-Security-Policy",
                    "value": value,
                },
                remediation=(
                    "Configure a meaningful Content-Security-Policy that "
                    "restricts applicable content sources."
                ),
            )

        weak_tokens = (
            "'unsafe-inline'",
            "'unsafe-eval'",
            "*",
        )

        matched = [
            token
            for token in weak_tokens
            if token in normalized
        ]

        if matched:
            return HeaderObservation(
                finding_type=WEAK_SECURITY_HEADER,
                title="Weak Content-Security-Policy",
                severity="Low",
                confidence="High",
                target=target,
                description=(
                    "The Content-Security-Policy contains directives or "
                    "source expressions that weaken its restrictions."
                ),
                evidence={
                    "header": "Content-Security-Policy",
                    "value": value,
                    "weak_elements": matched,
                },
                remediation=(
                    "Review the Content-Security-Policy and remove "
                    "unnecessary unsafe or overly broad source expressions."
                ),
            )

        return None

    # ------------------------------------------------------------------
    # Strict-Transport-Security
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_hsts(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate basic HSTS configuration.
        """

        normalized = value.lower()

        max_age_match = None

        for directive in normalized.split(";"):
            directive = directive.strip()

            if directive.startswith("max-age="):
                max_age_match = directive.split(
                    "=",
                    1,
                )[1].strip()
                break

        if max_age_match is None:
            return HeaderObservation(
                finding_type=SECURITY_HEADER_MISCONFIGURATION,
                title="Misconfigured Strict-Transport-Security",
                severity="Medium",
                confidence="High",
                target=target,
                description=(
                    "The Strict-Transport-Security header is present but "
                    "does not define a max-age directive."
                ),
                evidence={
                    "header": "Strict-Transport-Security",
                    "value": value,
                },
                remediation=(
                    "Configure Strict-Transport-Security with an "
                    "appropriate max-age value."
                ),
            )

        try:
            max_age = int(max_age_match)
        except ValueError:
            max_age = -1

        if max_age < 0:
            return HeaderObservation(
                finding_type=SECURITY_HEADER_MISCONFIGURATION,
                title="Misconfigured Strict-Transport-Security",
                severity="Medium",
                confidence="High",
                target=target,
                description=(
                    "The Strict-Transport-Security max-age directive "
                    "does not contain a valid integer value."
                ),
                evidence={
                    "header": "Strict-Transport-Security",
                    "value": value,
                },
                remediation=(
                    "Configure Strict-Transport-Security with a valid "
                    "max-age value."
                ),
            )

        if max_age < 31536000:
            return HeaderObservation(
                finding_type=WEAK_SECURITY_HEADER,
                title="Weak Strict-Transport-Security Configuration",
                severity="Low",
                confidence="High",
                target=target,
                description=(
                    "Strict-Transport-Security is enabled with a max-age "
                    "shorter than one year."
                ),
                evidence={
                    "header": "Strict-Transport-Security",
                    "value": value,
                    "max_age": max_age,
                },
                remediation=(
                    "Review the HSTS policy and consider an appropriate "
                    "long-term max-age for the application."
                ),
            )

        return None

    # ------------------------------------------------------------------
    # X-Frame-Options
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_x_frame_options(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate X-Frame-Options.
        """

        normalized = value.strip().upper()

        if normalized not in (
            "DENY",
            "SAMEORIGIN",
        ):
            return HeaderObservation(
                finding_type=SECURITY_HEADER_MISCONFIGURATION,
                title="Misconfigured X-Frame-Options",
                severity="Medium",
                confidence="High",
                target=target,
                description=(
                    "The X-Frame-Options header contains a value that "
                    "is not a recognized DENY or SAMEORIGIN policy."
                ),
                evidence={
                    "header": "X-Frame-Options",
                    "value": value,
                },
                remediation=(
                    "Configure X-Frame-Options with an appropriate "
                    "DENY or SAMEORIGIN policy."
                ),
            )

        return None

    # ------------------------------------------------------------------
    # X-Content-Type-Options
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_x_content_type_options(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate X-Content-Type-Options.
        """

        if value.strip().lower() != "nosniff":
            return HeaderObservation(
                finding_type=SECURITY_HEADER_MISCONFIGURATION,
                title="Misconfigured X-Content-Type-Options",
                severity="Low",
                confidence="High",
                target=target,
                description=(
                    "The X-Content-Type-Options header is present but "
                    "does not use the expected nosniff value."
                ),
                evidence={
                    "header": "X-Content-Type-Options",
                    "value": value,
                },
                remediation=(
                    "Configure X-Content-Type-Options with the nosniff "
                    "directive."
                ),
            )

        return None

    # ------------------------------------------------------------------
    # Referrer-Policy
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_referrer_policy(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate Referrer-Policy for explicitly weak policies.
        """

        normalized = value.strip().lower()

        weak_policies = {
            "unsafe-url",
            "no-referrer-when-downgrade",
        }

        if normalized in weak_policies:
            return HeaderObservation(
                finding_type=WEAK_SECURITY_HEADER,
                title="Weak Referrer-Policy",
                severity="Low",
                confidence="High",
                target=target,
                description=(
                    "The Referrer-Policy permits broader referrer "
                    "information disclosure than more restrictive policies."
                ),
                evidence={
                    "header": "Referrer-Policy",
                    "value": value,
                },
                remediation=(
                    "Review the Referrer-Policy and consider a more "
                    "restrictive policy appropriate for the application."
                ),
            )

        return None

    # ------------------------------------------------------------------
    # Permissions-Policy
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_permissions_policy(
        target: str,
        value: str,
    ) -> HeaderObservation | None:
        """
        Evaluate clearly broad Permissions-Policy directives.
        """

        normalized = value.lower()

        if "(*)" in normalized:
            return HeaderObservation(
                finding_type=WEAK_SECURITY_HEADER,
                title="Weak Permissions-Policy",
                severity="Low",
                confidence="High",
                target=target,
                description=(
                    "The Permissions-Policy contains a wildcard origin "
                    "allowance for at least one controlled feature."
                ),
                evidence={
                    "header": "Permissions-Policy",
                    "value": value,
                },
                remediation=(
                    "Review Permissions-Policy directives and restrict "
                    "feature access to only the origins that require it."
                ),
            )

        return None


###############################################################################
# Public API
###############################################################################


HTTPHeadersAnalyzer = HeadersAnalyzer


__all__ = [
    "MISSING_SECURITY_HEADER",
    "WEAK_SECURITY_HEADER",
    "SECURITY_HEADER_MISCONFIGURATION",
    "SECURITY_HEADERS",
    "HeaderObservation",
    "HeadersAnalyzer",
    "HTTPHeadersAnalyzer",
]
