"""
ScopeForgeX CORS Security Analyzer
===================================

ScopeForgeX-native analyzer for Cross-Origin Resource Sharing (CORS)
configuration.

The analyzer consumes HTTP response evidence collected by enumeration
capabilities and produces normalized security findings.

It does not execute an external security tool.

Analyzed headers
----------------
- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials
- Access-Control-Allow-Methods
- Access-Control-Allow-Headers

Finding types
-------------
- CORS_MISCONFIGURATION

Design Principles
-----------------
- Native ScopeForgeX analysis.
- No external executable dependency.
- Structured findings.
- Preserve source evidence.
- Deterministic analysis.
- Standard-library only.
- Compatible with the canonical finding model.

Important
---------
CORS configuration is contextual. A permissive policy is not automatically
a vulnerability in every application. The analyzer therefore reports
configuration conditions as findings/observations that require contextual
validation.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Finding
###############################################################################


@dataclass(slots=True)
class CORSFinding:
    """
    Normalized CORS finding produced by the analyzer.
    """

    finding_type: str

    title: str

    severity: str

    confidence: str

    target: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    source_tool: str = "scopeforgex"

    detection_method: str = (
        "CORS Security Analyzer"
    )

    remediation: str = ""

    category: str = "cors_configuration"

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the finding into a stable dictionary.
        """

        return {
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "category": self.category,
            "description": self.description,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "remediation": self.remediation,
        }


###############################################################################
# Analyzer
###############################################################################


class CORSSecurityAnalyzer:
    """
    Analyze HTTP CORS response configuration.

    Expected input:

        {
            "target": "https://example.com",
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        }

    Header names are matched case-insensitively.
    """

    name = "cors_security"

    description = (
        "Analyze Cross-Origin Resource Sharing configuration for "
        "potentially unsafe origin and credential handling."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[CORSFinding]:
        """
        Analyze CORS response headers.

        Returns:
            A list of normalized CORSFinding objects.
        """

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        headers = evidence.get(
            "headers",
            {},
        )

        if not isinstance(
            headers,
            Mapping,
        ):
            return []

        normalized = self._normalize_headers(
            headers
        )

        findings: list[CORSFinding] = []

        allow_origin = normalized.get(
            "access-control-allow-origin"
        )

        allow_credentials = normalized.get(
            "access-control-allow-credentials"
        )

        allow_methods = normalized.get(
            "access-control-allow-methods"
        )

        allow_headers = normalized.get(
            "access-control-allow-headers"
        )

        #######################################################################
        # Wildcard origin with credentials
        #######################################################################

        if (
            allow_origin == "*"
            and self._is_true(
                allow_credentials
            )
        ):

            findings.append(
                self._finding(
                    target=target,
                    title=(
                        "CORS Allows Wildcard Origin With Credentials"
                    ),
                    severity="high",
                    confidence="high",
                    description=(
                        "The response permits all origins through a "
                        "wildcard Access-Control-Allow-Origin value while "
                        "also enabling credentials."
                    ),
                    evidence={
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": (
                            allow_credentials
                        ),
                    },
                    remediation=(
                        "Do not combine a wildcard origin with credentialed "
                        "cross-origin access. Restrict allowed origins to "
                        "trusted origins."
                    ),
                )
            )

        #######################################################################
        # Origin reflection indicator
        #######################################################################

        if self._looks_like_reflection(
            allow_origin
        ):

            findings.append(
                self._finding(
                    target=target,
                    title=(
                        "Potentially Reflected CORS Origin"
                    ),
                    severity="medium",
                    confidence="medium",
                    description=(
                        "The collected CORS evidence indicates that the "
                        "Access-Control-Allow-Origin value may reflect an "
                        "origin supplied by the requester."
                    ),
                    evidence={
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": (
                            allow_credentials
                        ),
                    },
                    remediation=(
                        "Validate the request Origin against an explicit "
                        "allowlist of trusted origins rather than blindly "
                        "reflecting arbitrary origins."
                    ),
                )
            )

        #######################################################################
        # Wildcard origin
        #######################################################################

        elif allow_origin == "*":

            findings.append(
                self._finding(
                    target=target,
                    title=(
                        "Permissive CORS Wildcard Origin"
                    ),
                    severity="low",
                    confidence="high",
                    description=(
                        "The response permits requests from arbitrary "
                        "origins through Access-Control-Allow-Origin: *."
                    ),
                    evidence={
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": (
                            allow_credentials
                        ),
                    },
                    remediation=(
                        "If cross-origin access is not intentionally "
                        "public, restrict Access-Control-Allow-Origin to "
                        "specific trusted origins."
                    ),
                )
            )

        #######################################################################
        # Credentialed arbitrary origin indicator
        #######################################################################

        if (
            allow_origin
            and allow_origin != "*"
            and self._is_true(
                allow_credentials
            )
        ):

            findings.append(
                self._finding(
                    target=target,
                    title=(
                        "Credentialed Cross-Origin Access Requires "
                        "Origin Validation"
                    ),
                    severity="informational",
                    confidence="medium",
                    description=(
                        "The response enables credentialed cross-origin "
                        "requests for a specific origin. The origin should "
                        "be verified as trusted and intentionally permitted."
                    ),
                    evidence={
                        "access_control_allow_origin": allow_origin,
                        "access_control_allow_credentials": (
                            allow_credentials
                        ),
                    },
                    remediation=(
                        "Ensure credentialed CORS is limited to explicitly "
                        "trusted origins and required application flows."
                    ),
                )
            )

        #######################################################################
        # Broad methods
        #######################################################################

        if allow_methods:

            methods = self._split_values(
                allow_methods
            )

            dangerous_methods = {
                "PUT",
                "DELETE",
                "PATCH",
            }

            exposed_dangerous = sorted(
                methods.intersection(
                    dangerous_methods
                )
            )

            if exposed_dangerous:

                findings.append(
                    self._finding(
                        target=target,
                        title=(
                            "CORS Exposes State-Changing HTTP Methods"
                        ),
                        severity="low",
                        confidence="medium",
                        description=(
                            "The CORS policy permits one or more "
                            "state-changing HTTP methods."
                        ),
                        evidence={
                            "access_control_allow_methods": (
                                allow_methods
                            ),
                            "state_changing_methods": (
                                exposed_dangerous
                            ),
                        },
                        remediation=(
                            "Allow only the HTTP methods required by the "
                            "cross-origin application workflow."
                        ),
                    )
                )

        #######################################################################
        # Broad request headers
        #######################################################################

        if allow_headers:

            if "*" in self._split_values(
                allow_headers
            ):

                findings.append(
                    self._finding(
                        target=target,
                        title=(
                            "CORS Allows Wildcard Request Headers"
                        ),
                        severity="low",
                        confidence="medium",
                        description=(
                            "The CORS policy permits arbitrary request "
                            "headers through a wildcard "
                            "Access-Control-Allow-Headers value."
                        ),
                        evidence={
                            "access_control_allow_headers": (
                                allow_headers
                            ),
                        },
                        remediation=(
                            "Restrict allowed request headers to those "
                            "required by the application."
                        ),
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Header normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_headers(
        headers: Mapping[str, Any],
    ) -> dict[str, str]:
        """
        Normalize HTTP header names and values.
        """

        normalized: dict[str, str] = {}

        for name, value in headers.items():

            if name is None:
                continue

            key = str(
                name
            ).strip().lower()

            if not key:
                continue

            normalized[key] = str(
                value
            ).strip()

        return normalized

    # ------------------------------------------------------------------
    # Value helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_true(
        value: str | None,
    ) -> bool:
        """
        Determine whether a header value represents true.
        """

        if value is None:
            return False

        return value.strip().lower() == "true"

    @staticmethod
    def _split_values(
        value: str,
    ) -> set[str]:
        """
        Split comma-separated CORS values.
        """

        return {
            item.strip().upper()
            for item in value.split(",")
            if item.strip()
        }

    @staticmethod
    def _looks_like_reflection(
        value: str | None,
    ) -> bool:
        """
        Detect obvious origin-reflection indicators in collected evidence.

        A literal reflected value cannot be proven from a single response
        unless the captured evidence explicitly records request-origin
        information. This method therefore only recognizes explicit markers
        rather than claiming that every specific origin is vulnerable.
        """

        if not value:
            return False

        lowered = value.strip().lower()

        return lowered in {
            "reflected",
            "$origin",
            "${origin}",
            "{{origin}}",
            "<origin>",
            "request-origin",
        }

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    @staticmethod
    def _finding(
        *,
        target: str,
        title: str,
        severity: str,
        confidence: str,
        description: str,
        evidence: dict[str, Any],
        remediation: str,
    ) -> CORSFinding:
        """
        Construct a normalized CORS finding.
        """

        return CORSFinding(
            finding_type="CORS_MISCONFIGURATION",
            title=title,
            severity=severity,
            confidence=confidence,
            target=target,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )


###############################################################################
# Convenience Function
###############################################################################


def analyze_cors(
    evidence: Mapping[str, Any],
) -> list[CORSFinding]:
    """
    Analyze CORS configuration using the default analyzer.
    """

    analyzer = CORSSecurityAnalyzer()

    return analyzer.analyze(
        evidence
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "CORSFinding",
    "CORSSecurityAnalyzer",
    "analyze_cors",
]
