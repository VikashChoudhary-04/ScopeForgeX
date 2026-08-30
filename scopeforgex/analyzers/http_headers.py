"""
ScopeForgeX HTTP Security Header Analyzer
==========================================

ScopeForgeX-native analyzer for deterministic HTTP response security-header
analysis.

The analyzer consumes HTTP response evidence already collected by the
ScopeForgeX workflow. It does not perform network requests and does not
execute external tools.

Analyzed headers
----------------
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
- Native ScopeForgeX capability.
- Analyze collected evidence only.
- No network access.
- No external executable dependency.
- Preserve source evidence.
- Produce structured observations.
- Detection is not confirmation.
- Header analysis is configuration analysis.
- The analyzer does not replace generic vulnerability scanners.

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
SECURITY_HEADER_MISCONFIGURATION = (
    "SECURITY_HEADER_MISCONFIGURATION"
)

SUPPORTED_HEADERS = (
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

    The observation represents a configuration condition identified in
    already-collected HTTP response evidence.
    """

    finding_type: str

    title: str

    severity: str

    confidence: str

    target: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict,
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
        Serialize the observation into a stable dictionary.
        """

        return {
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "description": self.description,
            "evidence": dict(
                self.evidence
            ),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "remediation": self.remediation,
            "category": self.category,
        }


###############################################################################
# Analyzer
###############################################################################


class HttpSecurityHeaderAnalyzer:
    """
    Analyze collected HTTP response security headers.

    Supported evidence forms include:

        {
            "target": "https://example.com",
            "headers": {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security":
                    "max-age=31536000",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy":
                    "strict-origin-when-cross-origin",
                "Permissions-Policy":
                    "camera=(), microphone=()",
            },
        }

    HTTP response records are also supported:

        {
            "target": "https://example.com",
            "responses": [
                {
                    "url": "https://example.com/",
                    "headers": {
                        "X-Frame-Options": "SAMEORIGIN",
                    },
                },
            ],
        }

    Header names are matched case-insensitively.

    The analyzer only inspects supplied evidence.
    """

    name = "http_security_headers"

    description = (
        "Analyze collected HTTP response security headers for missing, "
        "weak or misconfigured security controls."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[HeaderObservation]:
        """
        Analyze collected HTTP response evidence.

        Returns:
            A list of normalized HeaderObservation objects.

        Raises:
            TypeError:
                If evidence is not a mapping.
        """

        if not isinstance(
            evidence,
            Mapping,
        ):
            raise TypeError(
                "HTTP security header evidence must be a mapping."
            )

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        records = self._extract_records(
            evidence
        )

        if not records:
            records = [
                evidence
            ]

        observations: list[
            HeaderObservation
        ] = []

        seen: set[
            tuple[str, str, str, str]
        ] = set()

        for record in records:

            record_target = str(
                record.get(
                    "url",
                    record.get(
                        "target",
                        target,
                    ),
                )
            ).strip()

            if not record_target:
                record_target = target

            headers = self._extract_headers(
                record
            )

            if not headers:
                continue

            record_observations = (
                self._analyze_headers(
                    target=record_target,
                    headers=headers,
                )
            )

            for observation in record_observations:

                key = (
                    observation.finding_type,
                    observation.target,
                    observation.title,
                    str(
                        observation.evidence
                    ),
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                observations.append(
                    observation
                )

        return observations

    ###########################################################################
    # Evidence Extraction
    ###########################################################################

    @staticmethod
    def _extract_records(
        evidence: Mapping[str, Any],
    ) -> list[Mapping[str, Any]]:
        """
        Extract HTTP response records from collected evidence.
        """

        records: list[
            Mapping[str, Any]
        ] = []

        for key in (
            "responses",
            "http_responses",
            "documents",
        ):

            value = evidence.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                Mapping,
            ):

                records.append(
                    value
                )

                continue

            if isinstance(
                value,
                Iterable,
            ) and not isinstance(
                value,
                (str, bytes),
            ):

                for item in value:

                    if isinstance(
                        item,
                        Mapping,
                    ):

                        records.append(
                            item
                        )

        return records

    @classmethod
    def _extract_headers(
        cls,
        record: Mapping[str, Any],
    ) -> dict[str, str]:
        """
        Extract response headers from collected evidence.

        Supported locations:

        - headers
        - response_headers
        - response.headers
        """

        candidates: list[
            Mapping[str, Any]
        ] = []

        for key in (
            "headers",
            "response_headers",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                Mapping,
            ):

                candidates.append(
                    value
                )

        response = record.get(
            "response"
        )

        if isinstance(
            response,
            Mapping,
        ):

            response_headers = response.get(
                "headers"
            )

            if isinstance(
                response_headers,
                Mapping,
            ):

                candidates.append(
                    response_headers
                )

        normalized: dict[
            str,
            str,
        ] = {}

        for headers in candidates:

            for name, value in headers.items():

                if name is None:
                    continue

                header_name = str(
                    name
                ).strip().lower()

                if not header_name:
                    continue

                if value is None:
                    header_value = ""

                else:
                    header_value = str(
                        value
                    ).strip()

                normalized[
                    header_name
                ] = header_value

        return normalized

    ###########################################################################
    # Header Analysis
    ###########################################################################

    def _analyze_headers(
        self,
        *,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze all plan-defined security headers.
        """

        observations: list[
            HeaderObservation
        ] = []

        observations.extend(
            self._check_csp(
                target,
                headers,
            )
        )

        observations.extend(
            self._check_hsts(
                target,
                headers,
            )
        )

        observations.extend(
            self._check_x_frame_options(
                target,
                headers,
            )
        )

        observations.extend(
            self._check_x_content_type_options(
                target,
                headers,
            )
        )

        observations.extend(
            self._check_referrer_policy(
                target,
                headers,
            )
        )

        observations.extend(
            self._check_permissions_policy(
                target,
                headers,
            )
        )

        return observations

    ###########################################################################
    # Content-Security-Policy
    ###########################################################################

    def _check_csp(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze Content-Security-Policy.
        """

        name = "content-security-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Content-Security-Policy",
                    title=(
                        "Missing Content-Security-Policy Header"
                    ),
                    severity="Medium",
                    remediation=(
                        "Define a restrictive Content-Security-Policy "
                        "appropriate for the application."
                    ),
                )
            ]

        value = headers[name]
        lowered = value.lower()

        if (
            "'unsafe-inline'" in lowered
            or "'unsafe-eval'" in lowered
        ):

            return [
                self._weak(
                    target=target,
                    header="Content-Security-Policy",
                    value=value,
                    title=(
                        "Weak Content-Security-Policy Header"
                    ),
                    severity="Medium",
                    remediation=(
                        "Avoid unsafe-inline and unsafe-eval where "
                        "possible. Prefer nonces, hashes and restrictive "
                        "source policies."
                    ),
                )
            ]

        return []

    ###########################################################################
    # Strict-Transport-Security
    ###########################################################################

    def _check_hsts(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze Strict-Transport-Security.
        """

        name = "strict-transport-security"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Strict-Transport-Security",
                    title="Missing HSTS Header",
                    severity="Medium",
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
                    severity="Medium",
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
                    severity="Medium",
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
                    severity="Medium",
                    remediation=(
                        "Use a positive HSTS max-age appropriate for "
                        "the application's deployment."
                    ),
                )
            ]

        return []

    ###########################################################################
    # X-Frame-Options
    ###########################################################################

    def _check_x_frame_options(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze X-Frame-Options.
        """

        name = "x-frame-options"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="X-Frame-Options",
                    title=(
                        "Missing X-Frame-Options Header"
                    ),
                    severity="Low",
                    remediation=(
                        "Set X-Frame-Options to DENY or SAMEORIGIN, "
                        "or enforce an equivalent framing policy through "
                        "Content-Security-Policy."
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
                    title=(
                        "Misconfigured X-Frame-Options Header"
                    ),
                    severity="Low",
                    remediation=(
                        "Use DENY or SAMEORIGIN where appropriate."
                    ),
                )
            ]

        return []

    ###########################################################################
    # X-Content-Type-Options
    ###########################################################################

    def _check_x_content_type_options(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze X-Content-Type-Options.
        """

        name = "x-content-type-options"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="X-Content-Type-Options",
                    title=(
                        "Missing X-Content-Type-Options Header"
                    ),
                    severity="Low",
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
                        "Misconfigured "
                        "X-Content-Type-Options Header"
                    ),
                    severity="Low",
                    remediation=(
                        "Set X-Content-Type-Options to nosniff."
                    ),
                )
            ]

        return []

    ###########################################################################
    # Referrer-Policy
    ###########################################################################

    def _check_referrer_policy(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze Referrer-Policy.
        """

        name = "referrer-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Referrer-Policy",
                    title="Missing Referrer-Policy Header",
                    severity="Low",
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
                    severity="Low",
                    remediation=(
                        "Prefer a restrictive policy such as "
                        "strict-origin-when-cross-origin, same-origin "
                        "or no-referrer where appropriate."
                    ),
                )
            ]

        return []

    ###########################################################################
    # Permissions-Policy
    ###########################################################################

    def _check_permissions_policy(
        self,
        target: str,
        headers: Mapping[str, str],
    ) -> list[HeaderObservation]:
        """
        Analyze Permissions-Policy presence.

        Absence is treated as informational because the appropriate policy
        depends on the application's required browser capabilities.
        """

        name = "permissions-policy"

        if name not in headers:

            return [
                self._missing(
                    target=target,
                    header="Permissions-Policy",
                    title="Missing Permissions-Policy Header",
                    severity="Informational",
                    remediation=(
                        "Define a Permissions-Policy that restricts "
                        "browser features not required by the application."
                    ),
                )
            ]

        return []

    ###########################################################################
    # Finding Builders
    ###########################################################################

    @staticmethod
    def _missing(
        *,
        target: str,
        header: str,
        title: str,
        severity: str,
        remediation: str,
    ) -> HeaderObservation:
        """
        Construct a missing-header observation.
        """

        return HeaderObservation(
            finding_type=MISSING_SECURITY_HEADER,
            title=title,
            severity=severity,
            confidence="High",
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
    ) -> HeaderObservation:
        """
        Construct a weak-header observation.
        """

        return HeaderObservation(
            finding_type=WEAK_SECURITY_HEADER,
            title=title,
            severity=severity,
            confidence="High",
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
    ) -> HeaderObservation:
        """
        Construct a misconfiguration observation.
        """

        return HeaderObservation(
            finding_type=(
                SECURITY_HEADER_MISCONFIGURATION
            ),
            title=title,
            severity=severity,
            confidence="High",
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

    ###########################################################################
    # Directive Helpers
    ###########################################################################

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
# Backward-Compatible Alias
###############################################################################


HeaderFinding = HeaderObservation


###############################################################################
# Convenience Function
###############################################################################


def analyze_http_security_headers(
    evidence: Mapping[str, Any],
) -> list[HeaderObservation]:
    """
    Analyze collected HTTP security headers using the default analyzer.
    """

    analyzer = HttpSecurityHeaderAnalyzer()

    return analyzer.analyze(
        evidence
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "MISSING_SECURITY_HEADER",
    "WEAK_SECURITY_HEADER",
    "SECURITY_HEADER_MISCONFIGURATION",
    "SUPPORTED_HEADERS",
    "HeaderObservation",
    "HeaderFinding",
    "HttpSecurityHeaderAnalyzer",
    "analyze_http_security_headers",
]
