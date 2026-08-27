"""
ScopeForgeX HTTP Security Header Analyzer
==========================================

ScopeForgeX-native analyzer for HTTP response security headers.

The analyzer consumes HTTP response evidence collected by enumeration
capabilities such as HTTPX and produces normalized security findings.

It does not execute an external security tool.

Supported headers
-----------------
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Finding types
-------------
- MISSING_SECURITY_HEADER
- WEAK_SECURITY_HEADER
- SECURITY_HEADER_MISCONFIGURATION

Design Principles
-----------------
- Native ScopeForgeX analysis.
- No external executable dependency.
- Structured findings.
- Preserve source evidence.
- Deterministic analysis.
- Standard-library only.
- Compatible with the canonical finding model.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Constants
###############################################################################


SUPPORTED_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


###############################################################################
# Finding
###############################################################################


@dataclass(slots=True)
class HeaderFinding:
    """
    Normalized finding produced by the HTTP security header analyzer.

    This is intentionally lightweight so the analyzer does not depend on
    reporting or execution components.
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
        "HTTP Security Header Analyzer"
    )

    remediation: str = ""

    category: str = (
        "security_header_configuration"
    )

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


class HttpSecurityHeaderAnalyzer:
    """
    Analyze HTTP response security headers.

    Expected input
    ---------------

    A mapping containing a target and HTTP response headers.

    Example:

        {
            "target": "https://example.com",
            "headers": {
                "Content-Type": "text/html",
                "Server": "nginx",
                "X-Frame-Options": "SAMEORIGIN",
            },
        }

    Header names are matched case-insensitively.
    """

    name = "http_security_headers"

    description = (
        "Analyze HTTP response security headers for missing, weak or "
        "misconfigured security controls."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[HeaderFinding]:
        """
        Analyze HTTP response evidence.

        Returns:
            A list of normalized HeaderFinding objects.
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

        findings: list[HeaderFinding] = []

        findings.extend(
            self._check_csp(
                target,
                normalized,
            )
        )

        findings.extend(
            self._check_hsts(
                target,
                normalized,
            )
        )

        findings.extend(
            self._check_x_frame_options(
                target,
                normalized,
            )
        )

        findings.extend(
            self._check_x_content_type_options(
                target,
                normalized,
            )
        )

        findings.extend(
            self._check_referrer_policy(
                target,
                normalized,
            )
        )

        findings.extend(
            self._check_permissions_policy(
                target,
                normalized,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_headers(
        headers: Mapping[str, Any],
    ) -> dict[str, str]:
        """
        Normalize HTTP header names and values.

        Header names become lowercase. Values are converted to strings and
        surrounding whitespace is removed.
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
    # Content-Security-Policy
    # ------------------------------------------------------------------

    def _check_csp(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check Content-Security-Policy.
        """

        name = "content-security-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Content-Security-Policy",
                    title="Missing Content-Security-Policy Header",
                    severity="medium",
                    remediation=(
                        "Define a restrictive Content-Security-Policy "
                        "appropriate for the application."
                    ),
                )
            ]

        value = headers[name]

        lowered = value.lower()

        if (
            "unsafe-inline" in lowered
            or "unsafe-eval" in lowered
        ):

            return [
                self._weak(
                    target=target,
                    header="Content-Security-Policy",
                    value=value,
                    title=(
                        "Weak Content-Security-Policy Header"
                    ),
                    severity="medium",
                    remediation=(
                        "Avoid unsafe-inline and unsafe-eval where "
                        "possible. Prefer nonces, hashes and restrictive "
                        "source policies."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # HSTS
    # ------------------------------------------------------------------

    def _check_hsts(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check Strict-Transport-Security.
        """

        name = "strict-transport-security"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Strict-Transport-Security",
                    title="Missing HSTS Header",
                    severity="medium",
                    remediation=(
                        "Enable Strict-Transport-Security for HTTPS "
                        "applications with an appropriate max-age."
                    ),
                )
            ]

        value = headers[name]

        max_age = self._extract_directive(
            value,
            "max-age",
        )

        if max_age is None:

            return [
                self._misconfigured(
                    target=target,
                    header="Strict-Transport-Security",
                    value=value,
                    title="Misconfigured HSTS Header",
                    severity="medium",
                    remediation=(
                        "Configure Strict-Transport-Security with a "
                        "valid max-age directive."
                    ),
                )
            ]

        try:
            max_age_value = int(
                max_age
            )
        except ValueError:

            return [
                self._misconfigured(
                    target=target,
                    header="Strict-Transport-Security",
                    value=value,
                    title="Invalid HSTS max-age",
                    severity="medium",
                    remediation=(
                        "Set max-age to a valid numeric value."
                    ),
                )
            ]

        if max_age_value <= 0:

            return [
                self._weak(
                    target=target,
                    header="Strict-Transport-Security",
                    value=value,
                    title="Weak HSTS Configuration",
                    severity="medium",
                    remediation=(
                        "Use a positive HSTS max-age appropriate for "
                        "the application's deployment."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # X-Frame-Options
    # ------------------------------------------------------------------

    def _check_x_frame_options(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check X-Frame-Options.
        """

        name = "x-frame-options"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="X-Frame-Options",
                    title="Missing X-Frame-Options Header",
                    severity="low",
                    remediation=(
                        "Set X-Frame-Options to DENY or SAMEORIGIN, "
                        "or enforce an equivalent framing policy through CSP."
                    ),
                )
            ]

        value = headers[name].strip().upper()

        if value not in {
            "DENY",
            "SAMEORIGIN",
        }:

            return [
                self._misconfigured(
                    target=target,
                    header="X-Frame-Options",
                    value=headers[name],
                    title="Misconfigured X-Frame-Options Header",
                    severity="low",
                    remediation=(
                        "Use DENY or SAMEORIGIN where appropriate."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # X-Content-Type-Options
    # ------------------------------------------------------------------

    def _check_x_content_type_options(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check X-Content-Type-Options.
        """

        name = "x-content-type-options"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="X-Content-Type-Options",
                    title="Missing X-Content-Type-Options Header",
                    severity="low",
                    remediation=(
                        "Set X-Content-Type-Options to nosniff."
                    ),
                )
            ]

        value = headers[name].strip().lower()

        if value != "nosniff":

            return [
                self._misconfigured(
                    target=target,
                    header="X-Content-Type-Options",
                    value=headers[name],
                    title=(
                        "Misconfigured X-Content-Type-Options Header"
                    ),
                    severity="low",
                    remediation=(
                        "Set X-Content-Type-Options to nosniff."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # Referrer-Policy
    # ------------------------------------------------------------------

    def _check_referrer_policy(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check Referrer-Policy.
        """

        name = "referrer-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Referrer-Policy",
                    title="Missing Referrer-Policy Header",
                    severity="low",
                    remediation=(
                        "Set an explicit Referrer-Policy appropriate "
                        "for the application."
                    ),
                )
            ]

        value = headers[name].strip().lower()

        weak_policies = {
            "unsafe-url",
            "no-referrer-when-downgrade",
        }

        if value in weak_policies:

            return [
                self._weak(
                    target=target,
                    header="Referrer-Policy",
                    value=headers[name],
                    title="Weak Referrer-Policy",
                    severity="low",
                    remediation=(
                        "Prefer a restrictive policy such as "
                        "strict-origin-when-cross-origin, "
                        "same-origin or no-referrer where appropriate."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # Permissions-Policy
    # ------------------------------------------------------------------

    def _check_permissions_policy(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderFinding]:
        """
        Check Permissions-Policy presence.

        The analyzer intentionally treats absence as informational rather
        than automatically assigning a vulnerability severity because the
        appropriate policy depends on the application's feature requirements.
        """

        name = "permissions-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Permissions-Policy",
                    title="Missing Permissions-Policy Header",
                    severity="informational",
                    remediation=(
                        "Define a Permissions-Policy that restricts "
                        "browser features not required by the application."
                    ),
                )
            ]

        return []

    # ------------------------------------------------------------------
    # Finding Builders
    # ------------------------------------------------------------------

    @staticmethod
    def _missing(
        *,
        target: str,
        header: str,
        title: str,
        severity: str,
        remediation: str,
    ) -> HeaderFinding:
        """
        Construct a missing-header finding.
        """

        return HeaderFinding(
            finding_type="MISSING_SECURITY_HEADER",
            title=title,
            severity=severity,
            confidence="high",
            target=target,
            description=(
                f"The HTTP response does not contain the "
                f"{header} security header."
            ),
            evidence={
                "header": header,
                "present": False,
            },
            remediation=remediation,
        )

    @staticmethod
    def _weak(
        *,
        target: str,
        header: str,
        value: str,
        title: str,
        severity: str,
        remediation: str,
    ) -> HeaderFinding:
        """
        Construct a weak-header finding.
        """

        return HeaderFinding(
            finding_type="WEAK_SECURITY_HEADER",
            title=title,
            severity=severity,
            confidence="high",
            target=target,
            description=(
                f"The {header} header is present but its "
                "configuration may provide weaker protection."
            ),
            evidence={
                "header": header,
                "value": value,
                "present": True,
            },
            remediation=remediation,
        )

    @staticmethod
    def _misconfigured(
        *,
        target: str,
        header: str,
        value: str,
        title: str,
        severity: str,
        remediation: str,
    ) -> HeaderFinding:
        """
        Construct a misconfiguration finding.
        """

        return HeaderFinding(
            finding_type=(
                "SECURITY_HEADER_MISCONFIGURATION"
            ),
            title=title,
            severity=severity,
            confidence="high",
            target=target,
            description=(
                f"The {header} header is present but does "
                "not use an expected configuration."
            ),
            evidence={
                "header": header,
                "value": value,
                "present": True,
            },
            remediation=remediation,
        )

    @staticmethod
    def _extract_directive(
        value: str,
        directive: str,
    ) -> str | None:
        """
        Extract a directive value from a semicolon-separated header.
        """

        directive_lower = directive.lower()

        for part in value.split(";"):

            item = part.strip()

            if "=" not in item:
                continue

            key, directive_value = item.split(
                "=",
                1,
            )

            if (
                key.strip().lower()
                == directive_lower
            ):

                return directive_value.strip()

        return None


###############################################################################
# Convenience Function
###############################################################################


def analyze_http_security_headers(
    evidence: Mapping[str, Any],
) -> list[HeaderFinding]:
    """
    Analyze HTTP security headers using the default analyzer.
    """

    analyzer = HttpSecurityHeaderAnalyzer()

    return analyzer.analyze(
        evidence
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SUPPORTED_HEADERS",
    "HeaderFinding",
    "HttpSecurityHeaderAnalyzer",
    "analyze_http_security_headers",
]
