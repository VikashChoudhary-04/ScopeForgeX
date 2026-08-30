"""
ScopeForgeX SSRF Analyzer
==========================

Capability-oriented Server-Side Request Forgery (SSRF) analysis.

The analyzer performs passive analysis of supplied request and response
data. It does not make outbound requests and does not attempt exploitation.

Detection focuses on request parameters and response indicators that may
suggest SSRF-prone functionality.

Detection categories
--------------------
- SSRF_SENSITIVE_PARAMETER
- SSRF_URL_PARAMETER
- SSRF_INTERNAL_REFERENCE
- SSRF_METADATA_REFERENCE

Design Principles
-----------------
- Passive analysis only.
- No network interaction.
- Normalized Finding output.
- Evidence preserved in structured form.
- Severity and confidence are represented independently.
- Standard-library only.

v1.2.0
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from scopeforgex.models.finding import (
    Confidence,
    Finding,
    FindingEvidence,
)
from scopeforgex.runtime.enums import Severity


###############################################################################
# Constants
###############################################################################


URL_PARAMETER_NAMES = {
    "url",
    "uri",
    "uri",
    "link",
    "href",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "return_uri",
    "next",
    "next_url",
    "dest",
    "destination",
    "target",
    "target_url",
    "callback",
    "callback_url",
    "image",
    "image_url",
    "feed",
    "feed_url",
    "source",
    "source_url",
    "file",
    "file_url",
    "path",
}

SENSITIVE_PARAMETER_NAMES = {
    "url",
    "uri",
    "link",
    "href",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return_url",
    "return_uri",
    "next_url",
    "dest",
    "destination",
    "target",
    "target_url",
    "callback",
    "callback_url",
    "image_url",
    "feed_url",
    "source_url",
}

INTERNAL_HOST_PATTERNS = (
    re.compile(
        r"^localhost$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^127(?:\.\d{1,3}){3}$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^0\.0\.0\.0$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^::1$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^fc00:",
        re.IGNORECASE,
    ),
    re.compile(
        r"^fd[0-9a-f]{2}:",
        re.IGNORECASE,
    ),
)

METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
}

INTERNAL_HOST_SUFFIXES = (
    ".localhost",
    ".internal",
    ".local",
    ".lan",
    ".corp",
    ".intranet",
)

###############################################################################
# Helpers
###############################################################################


def _normalize_parameter_name(
    name: str,
) -> str:
    """
    Normalize a parameter name for comparison.
    """

    return (
        str(name)
        .strip()
        .lower()
        .replace("-", "_")
    )


def _is_url_parameter(
    name: str,
) -> bool:
    """
    Return True when a parameter name commonly represents a URL or
    remotely retrieved resource.
    """

    normalized = _normalize_parameter_name(
        name
    )

    return (
        normalized in URL_PARAMETER_NAMES
        or normalized.endswith("_url")
        or normalized.endswith("_uri")
    )


def _is_sensitive_parameter(
    name: str,
) -> bool:
    """
    Return True when a parameter is commonly associated with SSRF-prone
    functionality.
    """

    normalized = _normalize_parameter_name(
        name
    )

    return (
        normalized in SENSITIVE_PARAMETER_NAMES
        or normalized.endswith("_url")
        or normalized.endswith("_uri")
    )


def _extract_query_parameters(
    url: str,
) -> list[tuple[str, str]]:
    """
    Extract query parameters from a URL.
    """

    try:
        parsed = urlparse(
            url
        )

        return parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

    except ValueError:
        return []


def _is_internal_host(
    host: str,
) -> bool:
    """
    Return True when a hostname represents a common internal destination.

    This intentionally uses conservative indicators rather than attempting
    complete IP address classification.
    """

    normalized = (
        host
        .strip()
        .lower()
        .rstrip(".")
    )

    if not normalized:
        return False

    for pattern in INTERNAL_HOST_PATTERNS:
        if pattern.match(
            normalized
        ):
            return True

    return normalized.endswith(
        INTERNAL_HOST_SUFFIXES
    )


def _is_metadata_host(
    host: str,
) -> bool:
    """
    Return True when a hostname is associated with common cloud metadata
    endpoints.
    """

    return (
        host
        .strip()
        .lower()
        .rstrip(".")
        in METADATA_HOSTS
    )


def _extract_host(
    value: str,
) -> str:
    """
    Extract a hostname from a URL-like value.
    """

    candidate = (
        value
        .strip()
    )

    if not candidate:
        return ""

    try:
        parsed = urlparse(
            candidate
        )

        if parsed.hostname:
            return parsed.hostname

    except ValueError:
        return ""

    return ""


def _finding(
    *,
    target: str,
    url: str,
    category: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    impact: str,
    remediation: str,
    parameter: str = "",
    evidence_value: str = "",
    detection_method: str,
) -> Finding:
    """
    Construct a normalized SSRF finding.
    """

    evidence = FindingEvidence(
        description=(
            "Passive SSRF indicator analysis."
        ),
        request=(
            f"{parameter}={evidence_value}"
            if parameter
            else ""
        ),
        metadata={
            "parameter": parameter,
            "value": evidence_value,
        },
    )

    return Finding(
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        target=target,
        url=url,
        parameter=parameter,
        description=description,
        impact=impact,
        remediation=remediation,
        evidence=evidence,
        source_tool="ssrf_analyzer",
        detection_method=detection_method,
    )


###############################################################################
# Analyzer
###############################################################################


class SSRFAnalyzer:
    """
    Analyze supplied HTTP request data for passive SSRF indicators.

    The analyzer does not send requests or interact with internal services.
    """

    name = "ssrf"

    display_name = "SSRF Analyzer"

    description = (
        "Analyze HTTP request data for potential "
        "Server-Side Request Forgery indicators."
    )

    capability = (
        "ssrf_security_analysis"
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        target: str,
        url: str,
        method: str = "GET",
        parameters: dict[str, Any] | None = None,
        request_body: str = "",
        response_body: str = "",
    ) -> list[Finding]:
        """
        Analyze supplied request and response data.

        Parameters
        ----------
        target:
            Assessment target.

        url:
            URL associated with the request.

        method:
            HTTP method.

        parameters:
            Parsed request parameters.

        request_body:
            Raw request body when available.

        response_body:
            Raw response body when available.

        Returns
        -------
        list[Finding]
            Normalized SSRF findings.

        Notes
        -----
        A URL-valued parameter alone is not proof of SSRF. The analyzer
        therefore reports such parameters as potential SSRF attack surfaces
        with informational/low severity rather than as confirmed
        vulnerabilities.
        """

        findings: list[Finding] = []

        supplied_parameters: dict[str, Any] = {}

        if isinstance(
            parameters,
            dict,
        ):
            supplied_parameters.update(
                parameters
            )

        for name, value in _extract_query_parameters(
            url
        ):
            supplied_parameters.setdefault(
                name,
                value,
            )

        #######################################################################
        # Parameter analysis
        #######################################################################

        for parameter, raw_value in supplied_parameters.items():

            parameter_name = str(
                parameter
            )

            value = str(
                raw_value
            ).strip()

            if not value:
                continue

            if not _is_url_parameter(
                parameter_name
            ):
                continue

            host = _extract_host(
                value
            )

            ###################################################################
            # Cloud metadata endpoint
            ###################################################################

            if host and _is_metadata_host(
                host
            ):

                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        category=(
                            "SSRF_METADATA_REFERENCE"
                        ),
                        title=(
                            "Cloud Metadata Endpoint Reference"
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        parameter=parameter_name,
                        evidence_value=value,
                        description=(
                            "A request parameter contains a URL "
                            "pointing to a commonly used cloud "
                            "instance metadata endpoint."
                        ),
                        impact=(
                            "If the application fetches this URL "
                            "server-side, sensitive instance metadata "
                            "or temporary credentials may become "
                            "accessible."
                        ),
                        remediation=(
                            "Restrict outbound destinations using an "
                            "allowlist, validate URLs after parsing, "
                            "block cloud metadata endpoints and use "
                            "network-level egress controls."
                        ),
                        detection_method=(
                            "URL-valued parameter resolves to a known "
                            "cloud metadata hostname."
                        ),
                    )
                )

                continue

            ###################################################################
            # Internal destination
            ###################################################################

            if host and _is_internal_host(
                host
            ):

                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        category=(
                            "SSRF_INTERNAL_REFERENCE"
                        ),
                        title=(
                            "Internal Network Destination Reference"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        parameter=parameter_name,
                        evidence_value=value,
                        description=(
                            "A URL-valued request parameter references "
                            "a hostname commonly associated with a "
                            "local or internal network destination."
                        ),
                        impact=(
                            "If the application performs server-side "
                            "requests to user-controlled destinations, "
                            "internal services may become reachable."
                        ),
                        remediation=(
                            "Validate and restrict outbound "
                            "destinations. Block loopback, link-local "
                            "and private/internal destinations where "
                            "they are not explicitly required."
                        ),
                        detection_method=(
                            "URL-valued parameter contains a hostname "
                            "matching a known internal destination "
                            "pattern."
                        ),
                    )
                )

                continue

            ###################################################################
            # Generic URL-valued parameter
            ###################################################################

            if _is_sensitive_parameter(
                parameter_name
            ):

                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        category=(
                            "SSRF_SENSITIVE_PARAMETER"
                        ),
                        title=(
                            "Potential SSRF-Prone Parameter"
                        ),
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        parameter=parameter_name,
                        evidence_value=value,
                        description=(
                            "The request contains a parameter whose "
                            "name commonly indicates server-side "
                            "retrieval of a user-controlled resource."
                        ),
                        impact=(
                            "If the application retrieves the supplied "
                            "resource server-side without adequate "
                            "validation, the parameter may provide an "
                            "SSRF attack surface."
                        ),
                        remediation=(
                            "Determine whether the application performs "
                            "server-side requests using this parameter. "
                            "If so, restrict destinations with a strict "
                            "allowlist and apply network-level egress "
                            "controls."
                        ),
                        detection_method=(
                            "Parameter name indicates a URL, redirect "
                            "or remotely retrieved resource."
                        ),
                    )
                )

        #######################################################################
        # Request-body analysis
        #######################################################################

        body = str(
            request_body
            or ""
        )

        if body:

            body_lower = body.lower()

            metadata_markers = (
                "169.254.169.254",
                "metadata.google.internal",
                "metadata.google.com",
            )

            for marker in metadata_markers:

                if marker in body_lower:

                    findings.append(
                        _finding(
                            target=target,
                            url=url,
                            category=(
                                "SSRF_METADATA_REFERENCE"
                            ),
                            title=(
                                "Cloud Metadata Endpoint Reference"
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence_value=marker,
                            description=(
                                "The request body contains a reference "
                                "to a commonly used cloud metadata "
                                "endpoint."
                            ),
                            impact=(
                                "If server-side URL retrieval is "
                                "performed using this value, cloud "
                                "instance metadata or temporary "
                                "credentials may be exposed."
                            ),
                            remediation=(
                                "Restrict outbound destinations, "
                                "block metadata endpoints and apply "
                                "network-level egress controls."
                            ),
                            detection_method=(
                                "Known cloud metadata endpoint "
                                "detected in the request body."
                            ),
                        )
                    )

                    break

        #######################################################################
        # Response analysis
        #######################################################################

        response = str(
            response_body
            or ""
        )

        if response:

            response_lower = response.lower()

            internal_markers = (
                "localhost",
                "127.0.0.1",
                "169.254.169.254",
                "metadata.google.internal",
            )

            for marker in internal_markers:

                if marker in response_lower:

                    findings.append(
                        _finding(
                            target=target,
                            url=url,
                            category=(
                                "SSRF_INTERNAL_REFERENCE"
                            ),
                            title=(
                                "Internal Resource Reference in Response"
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            evidence_value=marker,
                            description=(
                                "The response contains an internal "
                                "resource reference that may indicate "
                                "server-side retrieval of an internal "
                                "destination."
                            ),
                            impact=(
                                "Internal resource references in "
                                "responses can provide evidence that "
                                "server-side request functionality "
                                "reached an internal destination."
                            ),
                            remediation=(
                                "Review server-side URL fetching "
                                "functionality and enforce strict "
                                "destination validation and egress "
                                "controls."
                            ),
                            detection_method=(
                                "Internal destination marker detected "
                                "in the response body."
                            ),
                        )
                    )

                    break

        return findings


###############################################################################
# Public API
###############################################################################


HTTPSecuritySSRFAnalyzer = SSRFAnalyzer


__all__ = [
    "SSRFAnalyzer",
    "HTTPSecuritySSRFAnalyzer",
]
