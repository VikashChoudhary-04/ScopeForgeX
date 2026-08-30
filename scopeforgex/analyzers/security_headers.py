"""
ScopeForgeX Security Headers Analyzer
=====================================

Native analyzer for evaluating HTTP security response headers.

The analyzer consumes HTTP response evidence collected by ScopeForgeX and
produces normalized security observations for the universal Finding pipeline.

Responsibilities
----------------

- Analyze HTTP security headers without invoking an external tool.
- Detect missing security headers.
- Detect weak or unsafe security-header configurations.
- Preserve the original header value as evidence.
- Produce deterministic, structured observations.
- Keep detection separate from correlation, deduplication, and final reporting.

Analyzed Headers
----------------

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

Architecture
------------

HTTPX / Katana / other HTTP collector
                |
                v
        HTTP Response Evidence
                |
                v
      SecurityHeadersAnalyzer
                |
                v
      Normalized Observations
                |
                v
         Finding Normalizer
                |
                v
       Correlation / Risk Engine
                |
                v
              Report

Design Principles
-----------------

- Missing headers are observations, not automatically confirmed
  vulnerabilities.
- Header strength depends on the actual value and target context.
- HTTPS is required before HSTS can be meaningfully assessed.
- CSP is evaluated conservatively; complex policies are not declared
  vulnerable merely because they contain unusual directives.
- The analyzer does not perform network requests.
- The analyzer does not execute external security tools.
- The analyzer does not perform global deduplication or correlation.
- Raw response evidence remains available to downstream components.

v1.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Constants
###############################################################################


ANALYZER_NAME = "security_headers"

CATEGORY_MISSING = "MISSING_SECURITY_HEADER"
CATEGORY_WEAK = "WEAK_SECURITY_HEADER"
CATEGORY_MISCONFIGURATION = "SECURITY_HEADER_MISCONFIGURATION"

DEFAULT_MISSING_SEVERITY = "Low"
DEFAULT_WEAK_SEVERITY = "Medium"
DEFAULT_CONFIDENCE = "High"

SUPPORTED_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


###############################################################################
# Observation
###############################################################################


@dataclass(slots=True)
class SecurityHeaderObservation:
    """
    Structured observation produced by the native security-header analyzer.

    This object is intentionally independent from the universal Finding model.
    The finding-normalization layer remains responsible for converting this
    observation into the canonical project-wide representation.
    """

    title: str

    description: str

    category: str

    target: str = ""

    host: str | None = None

    url: str | None = None

    header: str | None = None

    header_value: str | None = None

    severity: str = DEFAULT_MISSING_SEVERITY

    confidence: str = DEFAULT_CONFIDENCE

    source_tool: str = ANALYZER_NAME

    detection_method: str = (
        "Native HTTP Security Header Analysis"
    )

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    cwe: str | None = None

    references: list[str] = field(
        default_factory=list
    )

    impact: str = ""

    remediation: str = ""

    def as_dict(self) -> dict[str, Any]:
        """
        Convert the observation into a mapping suitable for the universal
        finding-normalization layer.
        """

        metadata = dict(self.metadata)

        if self.header:
            metadata.setdefault(
                "header",
                self.header,
            )

        if self.header_value is not None:
            metadata.setdefault(
                "header_value",
                self.header_value,
            )

        return {
            "title": self.title,
            "category": self.category,
            "target": self.target,
            "host": self.host,
            "url": self.url,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "cwe": self.cwe,
            "references": list(self.references),
            "impact": self.impact,
            "remediation": self.remediation,
            "metadata": metadata,
        }


###############################################################################
# Analyzer
###############################################################################


class SecurityHeadersAnalyzer:
    """
    Analyze HTTP response security headers.

    The analyzer is deliberately request-free. It operates entirely on
    supplied response evidence.
    """

    name = ANALYZER_NAME

    description = (
        "Analyze HTTP security headers for missing, weak, or "
        "misconfigured security controls."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def analyze(
        self,
        response: Any = None,
        *,
        target: str = "",
        headers: Mapping[str, Any] | None = None,
        status_code: int | None = None,
        **kwargs: Any,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze an HTTP response.

        Parameters
        ----------
        response:
            Optional HTTP response object or mapping. When supplied, headers,
            status code, and URL may be extracted automatically.

        target:
            Target URL or asset identifier.

        headers:
            Explicit HTTP response headers. This takes precedence over headers
            extracted from response.

        status_code:
            Optional HTTP response status code.

        Returns
        -------
        list[SecurityHeaderObservation]
            Structured security-header observations.
        """

        normalized_headers = self._normalize_headers(
            headers
            if headers is not None
            else self._extract_headers(response)
        )

        if not normalized_headers:
            return []

        effective_target = (
            target
            or self._extract_response_url(response)
            or ""
        )

        effective_status = (
            status_code
            if status_code is not None
            else self._extract_status_code(response)
        )

        observations: list[SecurityHeaderObservation] = []

        observations.extend(
            self._analyze_content_security_policy(
                normalized_headers,
                effective_target,
            )
        )

        observations.extend(
            self._analyze_hsts(
                normalized_headers,
                effective_target,
            )
        )

        observations.extend(
            self._analyze_frame_options(
                normalized_headers,
                effective_target,
            )
        )

        observations.extend(
            self._analyze_content_type_options(
                normalized_headers,
                effective_target,
            )
        )

        observations.extend(
            self._analyze_referrer_policy(
                normalized_headers,
                effective_target,
            )
        )

        observations.extend(
            self._analyze_permissions_policy(
                normalized_headers,
                effective_target,
            )
        )

        return self._deduplicate(
            observations
        )

    ###########################################################################
    # CSP
    ###########################################################################

    def _analyze_content_security_policy(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze Content-Security-Policy.

        The analyzer reports clearly weak CSP configurations while avoiding
        aggressive claims about policies that require application context.
        """

        header = "Content-Security-Policy"
        value = headers.get(
            "content-security-policy"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The response does not define a Content Security "
                        "Policy, reducing the browser-side controls available "
                        "against content injection and related attacks."
                    ),
                    impact=(
                        "Without CSP, exploitation of certain client-side "
                        "injection issues may be easier and browser-side "
                        "defense-in-depth is reduced."
                    ),
                    remediation=(
                        "Define a restrictive Content-Security-Policy that "
                        "allows only the scripts, styles, frames, images, "
                        "connections, and other resources required by the "
                        "application."
                    ),
                    cwe="CWE-693",
                )
            ]

        normalized = value.lower()

        if "'unsafe-eval'" in normalized:
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak Content-Security-Policy: unsafe-eval"
                    ),
                    description=(
                        "The Content-Security-Policy permits unsafe-eval, "
                        "which weakens restrictions on dynamically evaluated "
                        "JavaScript."
                    ),
                    impact=(
                        "unsafe-eval can reduce the effectiveness of CSP "
                        "against certain script-injection exploitation "
                        "paths."
                    ),
                    remediation=(
                        "Remove 'unsafe-eval' unless it is strictly required "
                        "by the application and cannot be replaced with safer "
                        "application behavior."
                    ),
                    cwe="CWE-693",
                )
            ]

        if re.search(
            r"(?:^|;)\s*(?:script-src|default-src)\s+[^;]*"
            r"\bunsafe-inline\b",
            normalized,
        ):
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak Content-Security-Policy: unsafe-inline"
                    ),
                    description=(
                        "The Content-Security-Policy permits unsafe-inline "
                        "for script execution, weakening restrictions on "
                        "inline JavaScript."
                    ),
                    impact=(
                        "unsafe-inline can significantly reduce CSP "
                        "protection against script injection."
                    ),
                    remediation=(
                        "Replace unsafe-inline with nonces or hashes where "
                        "possible and adopt a restrictive script-src policy."
                    ),
                    cwe="CWE-693",
                )
            ]

        if re.search(
            r"(?:^|;)\s*(?:script-src|default-src)\s+[^;]*"
            r"(?:^|\s)\*(?:\s|;|$)",
            normalized,
        ):
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak Content-Security-Policy: wildcard script source"
                    ),
                    description=(
                        "The Content-Security-Policy permits a wildcard "
                        "script source, providing weak restrictions on "
                        "where executable resources may originate."
                    ),
                    impact=(
                        "A permissive script source can reduce the defensive "
                        "value of CSP against malicious script inclusion."
                    ),
                    remediation=(
                        "Restrict script sources to trusted origins and "
                        "prefer nonces or hashes for application-controlled "
                        "scripts."
                    ),
                    cwe="CWE-693",
                )
            ]

        return []

    ###########################################################################
    # HSTS
    ###########################################################################

    def _analyze_hsts(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze Strict-Transport-Security.

        HSTS is only evaluated as a missing control for HTTPS targets.
        """

        if not self._is_https(target):
            return []

        header = "Strict-Transport-Security"
        value = headers.get(
            "strict-transport-security"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The HTTPS response does not define "
                        "Strict-Transport-Security."
                    ),
                    impact=(
                        "Without HSTS, browsers may remain susceptible to "
                        "protocol-downgrade and first-connection interception "
                        "scenarios."
                    ),
                    remediation=(
                        "Configure Strict-Transport-Security with an "
                        "appropriate max-age and consider includeSubDomains "
                        "and preload only after validating that all relevant "
                        "subdomains support HTTPS."
                    ),
                    cwe="CWE-319",
                )
            ]

        max_age_match = re.search(
            r"(?:^|;)\s*max-age\s*=\s*(\d+)",
            value,
            flags=re.IGNORECASE,
        )

        if not max_age_match:
            return [
                self._misconfiguration_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Misconfigured Strict-Transport-Security"
                    ),
                    description=(
                        "Strict-Transport-Security is present but does not "
                        "define a valid max-age directive."
                    ),
                    impact=(
                        "The browser may not enforce HSTS as intended."
                    ),
                    remediation=(
                        "Set a valid max-age value appropriate for the "
                        "application's HTTPS deployment."
                    ),
                    cwe="CWE-319",
                )
            ]

        max_age = int(
            max_age_match.group(1)
        )

        if max_age < 31536000:
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak Strict-Transport-Security policy"
                    ),
                    description=(
                        "The HSTS max-age is shorter than one year, reducing "
                        "the duration for which browsers remember the HTTPS "
                        "requirement."
                    ),
                    impact=(
                        "A short HSTS lifetime can reduce protection against "
                        "future downgrade or interception attempts."
                    ),
                    remediation=(
                        "Consider using an HSTS max-age of at least one year "
                        "after confirming that the application and its "
                        "subdomains are consistently available over HTTPS."
                    ),
                    cwe="CWE-319",
                )
            ]

        return []

    ###########################################################################
    # X-Frame-Options
    ###########################################################################

    def _analyze_frame_options(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze X-Frame-Options.
        """

        header = "X-Frame-Options"
        value = headers.get(
            "x-frame-options"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The response does not define X-Frame-Options. "
                        "Frame-embedding protection is therefore not "
                        "explicitly provided by this legacy browser control."
                    ),
                    impact=(
                        "Depending on application behavior and browser "
                        "support, the application may have reduced defense "
                        "against clickjacking."
                    ),
                    remediation=(
                        "Use Content-Security-Policy frame-ancestors as the "
                        "primary modern control and configure X-Frame-Options "
                        "where legacy browser compatibility is required."
                    ),
                    cwe="CWE-1021",
                )
            ]

        normalized = value.strip().lower()

        allowed = {
            "deny",
            "sameorigin",
        }

        if normalized not in allowed and not normalized.startswith(
            "allow-from "
        ):
            return [
                self._misconfiguration_observation(
                    header=header,
                    value=value,
                    target=target,
                    title="Invalid X-Frame-Options configuration",
                    description=(
                        "X-Frame-Options is present with a value that does "
                        "not match a recognized policy."
                    ),
                    impact=(
                        "An invalid or unsupported value may fail to provide "
                        "the intended clickjacking protection."
                    ),
                    remediation=(
                        "Use DENY or SAMEORIGIN as appropriate and configure "
                        "CSP frame-ancestors for modern browsers."
                    ),
                    cwe="CWE-1021",
                )
            ]

        return []

    ###########################################################################
    # X-Content-Type-Options
    ###########################################################################

    def _analyze_content_type_options(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze X-Content-Type-Options.
        """

        header = "X-Content-Type-Options"
        value = headers.get(
            "x-content-type-options"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The response does not define "
                        "X-Content-Type-Options."
                    ),
                    impact=(
                        "Browsers may perform MIME sniffing in situations "
                        "where strict content-type handling would provide "
                        "additional defense."
                    ),
                    remediation=(
                        "Set X-Content-Type-Options to nosniff for responses "
                        "where MIME sniffing should be prevented."
                    ),
                    cwe="CWE-693",
                )
            ]

        if value.strip().lower() != "nosniff":
            return [
                self._misconfiguration_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak X-Content-Type-Options configuration"
                    ),
                    description=(
                        "X-Content-Type-Options is present but does not use "
                        "the expected nosniff value."
                    ),
                    impact=(
                        "The header may not provide the intended protection "
                        "against MIME-type sniffing."
                    ),
                    remediation=(
                        "Set X-Content-Type-Options to nosniff."
                    ),
                    cwe="CWE-693",
                )
            ]

        return []

    ###########################################################################
    # Referrer-Policy
    ###########################################################################

    def _analyze_referrer_policy(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze Referrer-Policy.
        """

        header = "Referrer-Policy"
        value = headers.get(
            "referrer-policy"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The response does not define Referrer-Policy."
                    ),
                    impact=(
                        "URLs and path information may be disclosed through "
                        "the HTTP Referer header more broadly than necessary."
                    ),
                    remediation=(
                        "Configure an explicit restrictive policy such as "
                        "strict-origin-when-cross-origin according to the "
                        "application's privacy and functionality requirements."
                    ),
                    cwe="CWE-200",
                )
            ]

        normalized = value.strip().lower()

        weak_values = {
            "unsafe-url",
            "no-referrer-when-downgrade",
        }

        if normalized in weak_values:
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Weak Referrer-Policy configuration"
                    ),
                    description=(
                        "Referrer-Policy permits broader referrer disclosure "
                        "than a modern restrictive policy."
                    ),
                    impact=(
                        "Sensitive path or URL information may be disclosed "
                        "to external origins through referrer metadata."
                    ),
                    remediation=(
                        "Prefer a restrictive policy such as "
                        "strict-origin-when-cross-origin or no-referrer "
                        "where appropriate."
                    ),
                    cwe="CWE-200",
                )
            ]

        return []

    ###########################################################################
    # Permissions-Policy
    ###########################################################################

    def _analyze_permissions_policy(
        self,
        headers: Mapping[str, str],
        target: str,
    ) -> list[SecurityHeaderObservation]:
        """
        Analyze Permissions-Policy presence and obvious wildcard grants.
        """

        header = "Permissions-Policy"
        value = headers.get(
            "permissions-policy"
        )

        if value is None:
            return [
                self._missing_observation(
                    header=header,
                    target=target,
                    description=(
                        "The response does not define Permissions-Policy."
                    ),
                    impact=(
                        "Browser-controlled capabilities are not explicitly "
                        "restricted by this response header."
                    ),
                    remediation=(
                        "Define Permissions-Policy directives for browser "
                        "features that the application does not require."
                    ),
                    cwe="CWE-693",
                )
            ]

        if re.search(
            r"(?:^|[;,])\s*[\w-]+\s*=\s*\(\s*\*\s*\)",
            value,
        ):
            return [
                self._weak_observation(
                    header=header,
                    value=value,
                    target=target,
                    title=(
                        "Permissive Permissions-Policy configuration"
                    ),
                    description=(
                        "Permissions-Policy explicitly grants at least one "
                        "browser capability to all origins."
                    ),
                    impact=(
                        "Broad feature permissions can increase the browser "
                        "capabilities available to embedded or delegated "
                        "content."
                    ),
                    remediation=(
                        "Restrict each browser feature to the minimum origins "
                        "required by the application."
                    ),
                    cwe="CWE-693",
                )
            ]

        return []

    ###########################################################################
    # Observation factories
    ###########################################################################

    @staticmethod
    def _missing_observation(
        *,
        header: str,
        target: str,
        description: str,
        impact: str,
        remediation: str,
        cwe: str | None,
    ) -> SecurityHeaderObservation:
        """Create a missing-header observation."""

        return SecurityHeaderObservation(
            title=f"Missing {header}",
            description=description,
            category=CATEGORY_MISSING,
            target=target,
            host=SecurityHeadersAnalyzer._extract_host(
                target
            ),
            url=(
                target
                if SecurityHeadersAnalyzer._is_url(
                    target
                )
                else None
            ),
            header=header,
            header_value=None,
            severity=DEFAULT_MISSING_SEVERITY,
            confidence=DEFAULT_CONFIDENCE,
            evidence={
                "header": header,
                "observed_value": None,
            },
            metadata={
                "analyzer": ANALYZER_NAME,
                "observation_type": "missing",
            },
            cwe=cwe,
            impact=impact,
            remediation=remediation,
        )

    @staticmethod
    def _weak_observation(
        *,
        header: str,
        value: str,
        target: str,
        title: str,
        description: str,
        impact: str,
        remediation: str,
        cwe: str | None,
    ) -> SecurityHeaderObservation:
        """Create a weak-header observation."""

        return SecurityHeaderObservation(
            title=title,
            description=description,
            category=CATEGORY_WEAK,
            target=target,
            host=SecurityHeadersAnalyzer._extract_host(
                target
            ),
            url=(
                target
                if SecurityHeadersAnalyzer._is_url(
                    target
                )
                else None
            ),
            header=header,
            header_value=value,
            severity=DEFAULT_WEAK_SEVERITY,
            confidence=DEFAULT_CONFIDENCE,
            evidence={
                "header": header,
                "observed_value": value,
            },
            metadata={
                "analyzer": ANALYZER_NAME,
                "observation_type": "weak",
            },
            cwe=cwe,
            impact=impact,
            remediation=remediation,
        )

    @staticmethod
    def _misconfiguration_observation(
        *,
        header: str,
        value: str,
        target: str,
        title: str,
        description: str,
        impact: str,
        remediation: str,
        cwe: str | None,
    ) -> SecurityHeaderObservation:
        """Create a misconfiguration observation."""

        return SecurityHeaderObservation(
            title=title,
            description=description,
            category=CATEGORY_MISCONFIGURATION,
            target=target,
            host=SecurityHeadersAnalyzer._extract_host(
                target
            ),
            url=(
                target
                if SecurityHeadersAnalyzer._is_url(
                    target
                )
                else None
            ),
            header=header,
            header_value=value,
            severity=DEFAULT_WEAK_SEVERITY,
            confidence=DEFAULT_CONFIDENCE,
            evidence={
                "header": header,
                "observed_value": value,
            },
            metadata={
                "analyzer": ANALYZER_NAME,
                "observation_type": "misconfiguration",
            },
            cwe=cwe,
            impact=impact,
            remediation=remediation,
        )

    ###########################################################################
    # Header extraction
    ###########################################################################

    @staticmethod
    def _normalize_headers(
        headers: Mapping[str, Any] | None,
    ) -> dict[str, str]:
        """
        Normalize HTTP header names case-insensitively.

        If duplicate case variants are supplied, the last non-empty value
        wins.
        """

        if not headers:
            return {}

        normalized: dict[str, str] = {}

        for key, value in headers.items():

            name = str(key).strip().lower()

            if not name:
                continue

            if isinstance(
                value,
                (list, tuple),
            ):
                values = [
                    str(item).strip()
                    for item in value
                    if str(item).strip()
                ]

                if not values:
                    continue

                normalized[name] = ", ".join(
                    values
                )
                continue

            normalized_value = str(
                value
            ).strip()

            if normalized_value:
                normalized[name] = normalized_value

        return normalized

    @staticmethod
    def _extract_headers(
        response: Any,
    ) -> Mapping[str, Any] | None:
        """
        Extract headers from common response representations.
        """

        if response is None:
            return None

        if isinstance(
            response,
            Mapping,
        ):
            headers = response.get(
                "headers"
            )

            if isinstance(
                headers,
                Mapping,
            ):
                return headers

            return None

        headers = getattr(
            response,
            "headers",
            None,
        )

        if isinstance(
            headers,
            Mapping,
        ):
            return headers

        return None

    @staticmethod
    def _extract_response_url(
        response: Any,
    ) -> str:
        """Extract a response URL where available."""

        if response is None:
            return ""

        if isinstance(
            response,
            Mapping,
        ):
            return str(
                response.get(
                    "url",
                    ""
                )
                or ""
            ).strip()

        return str(
            getattr(
                response,
                "url",
                ""
            )
            or ""
        ).strip()

    @staticmethod
    def _extract_status_code(
        response: Any,
    ) -> int | None:
        """Extract an HTTP response status code."""

        if response is None:
            return None

        if isinstance(
            response,
            Mapping,
        ):
            value = response.get(
                "status_code"
            )

            if value is None:
                value = response.get(
                    "status"
                )
        else:
            value = getattr(
                response,
                "status_code",
                None,
            )

            if value is None:
                value = getattr(
                    response,
                    "status",
                    None,
                )

        try:
            return (
                int(value)
                if value is not None
                else None
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

    ###########################################################################
    # Target helpers
    ###########################################################################

    @staticmethod
    def _is_https(
        target: str,
    ) -> bool:
        """Return True when target is an HTTPS URL."""

        return bool(
            re.match(
                r"^https://",
                str(target).strip(),
                flags=re.IGNORECASE,
            )
        )

    @staticmethod
    def _is_url(
        target: str | None,
    ) -> bool:
        """Return True when target is an HTTP(S) URL."""

        if not target:
            return False

        return bool(
            re.match(
                r"^https?://",
                str(target).strip(),
                flags=re.IGNORECASE,
            )
        )

    @staticmethod
    def _extract_host(
        target: str | None,
    ) -> str | None:
        """Extract the host component from an HTTP(S) URL."""

        if not target:
            return None

        match = re.match(
            r"^https?://([^/:?#]+)",
            str(target).strip(),
            flags=re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(1)

    ###########################################################################
    # Deduplication
    ###########################################################################

    @staticmethod
    def _deduplicate(
        observations: list[SecurityHeaderObservation],
    ) -> list[SecurityHeaderObservation]:
        """
        Remove duplicate observations generated from duplicate header input.
        """

        unique: list[SecurityHeaderObservation] = []
        seen: set[tuple[str, str, str]] = set()

        for observation in observations:

            key = (
                observation.category,
                observation.header or "",
                observation.target,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(observation)

        return unique


###############################################################################
# Compatibility aliases
###############################################################################


Analyzer = SecurityHeadersAnalyzer


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SecurityHeadersAnalyzer",
    "SecurityHeaderObservation",
    "Analyzer",
    "ANALYZER_NAME",
    "CATEGORY_MISSING",
    "CATEGORY_WEAK",
    "CATEGORY_MISCONFIGURATION",
    "SUPPORTED_HEADERS",
]
