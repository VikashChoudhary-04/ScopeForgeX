"""
ScopeForgeX CORS Analyzer
=========================

Native analyzer for detecting Cross-Origin Resource Sharing (CORS)
misconfigurations from collected HTTP response evidence.

CORS analysis is performed entirely inside ScopeForgeX. No external
scanner is executed by this module.

Responsibilities
----------------

- Analyze HTTP response headers for CORS behavior.
- Inspect Access-Control-Allow-Origin.
- Inspect Access-Control-Allow-Credentials.
- Detect origin reflection when request-origin evidence is available.
- Identify dangerous wildcard credential combinations.
- Identify potentially unsafe reflected-origin configurations.
- Preserve the relevant HTTP response evidence.
- Produce normalized observations compatible with the universal Finding
  pipeline.

The analyzer does not:

- Execute external tools.
- Construct commands.
- Perform global finding correlation.
- Deduplicate findings across tools.
- Perform final report generation.
- Assume that every permissive CORS configuration is exploitable.

Architecture
------------

HTTP Response Evidence
        |
        v
CORSAnalyzer
        |
        v
Structured Observations
        |
        v
Finding Normalizer
        |
        v
Universal Finding Model
        |
        v
Correlation / Deduplication
        |
        v
Risk Classification

v1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


###############################################################################
# Constants
###############################################################################


ANALYZER_NAME = "cors"

CATEGORY_CORS = "CORS_MISCONFIGURATION"

DETECTION_METHOD = "ScopeForgeX CORS Analyzer"

DEFAULT_SEVERITY = "Medium"
DEFAULT_CONFIDENCE = "Medium"


###############################################################################
# Header helpers
###############################################################################


def _text(value: Any) -> str:
    """Return a normalized string representation."""

    if value is None:
        return ""

    return str(value).strip()


def _optional_text(value: Any) -> str | None:
    """Return normalized text or None when empty."""

    normalized = _text(value)

    return normalized or None


def _normalize_headers(
    headers: Any,
) -> dict[str, str]:
    """
    Normalize HTTP headers into a case-insensitive mapping.

    Supported forms include:

    - Mapping[str, str]
    - Mapping[str, list[str]]
    - Iterable of ``(name, value)`` pairs
    - Iterable of header-like objects
    """

    if headers is None:
        return {}

    normalized: dict[str, str] = {}

    if isinstance(headers, Mapping):
        for name, value in headers.items():

            key = _text(name).lower()

            if not key:
                continue

            if isinstance(value, (list, tuple)):
                values = [
                    _text(item)
                    for item in value
                    if _text(item)
                ]

                if values:
                    normalized[key] = ", ".join(values)

            else:
                value_text = _text(value)

                if value_text:
                    normalized[key] = value_text

        return normalized

    if isinstance(headers, str):
        for line in headers.splitlines():

            if ":" not in line:
                continue

            name, value = line.split(
                ":",
                1,
            )

            key = name.strip().lower()
            value_text = value.strip()

            if key and value_text:
                normalized[key] = value_text

        return normalized

    if isinstance(headers, Iterable):

        for item in headers:

            if isinstance(item, (list, tuple)) and len(item) >= 2:

                key = _text(item[0]).lower()
                value = _text(item[1])

                if key and value:
                    normalized[key] = value

        return normalized

    return {}


###############################################################################
# Observation
###############################################################################


@dataclass(slots=True)
class CORSObservation:
    """
    Structured CORS observation.

    This lightweight representation is converted into the universal Finding
    model by the surrounding finding pipeline.
    """

    title: str

    description: str

    target: str = ""

    host: str | None = None

    port: int | None = None

    url: str | None = None

    severity: str = DEFAULT_SEVERITY

    confidence: str = DEFAULT_CONFIDENCE

    source_tool: str = ANALYZER_NAME

    detection_method: str = DETECTION_METHOD

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def as_dict(self) -> dict[str, Any]:
        """
        Convert the observation into a normalized finding-compatible mapping.
        """

        return {
            "type": "vulnerability",
            "category": CATEGORY_CORS,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "metadata": dict(self.metadata),
        }


###############################################################################
# Analyzer
###############################################################################


class CORSAnalyzer:
    """
    Analyze HTTP response evidence for CORS security issues.

    The analyzer is intentionally conservative. A permissive CORS policy is
    not automatically considered exploitable. Stronger findings require
    evidence such as credentialed wildcard access or reflected origins.
    """

    name = ANALYZER_NAME

    category = CATEGORY_CORS

    description = (
        "Analyze HTTP CORS response headers for potentially unsafe "
        "cross-origin access configurations."
    )

    ###########################################################################
    # Public interface
    ###########################################################################

    def analyze(
        self,
        response: Any,
        *,
        target: str = "",
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        request_origin: str | None = None,
        **kwargs: Any,
    ) -> list[CORSObservation]:
        """
        Analyze a collected HTTP response.

        ``response`` may be:

        - a response-like object,
        - a mapping containing ``headers``,
        - a mapping containing ``response_headers``,
        - or a mapping whose keys are HTTP header names.

        ``request_origin`` should be supplied when the original request
        contained an Origin header. This enables reflected-origin detection.
        """

        headers = self._extract_headers(
            response
        )

        if not headers:
            return []

        effective_url = (
            url
            or self._extract_url(
                response
            )
            or (
                target
                if self._is_url(target)
                else None
            )
        )

        effective_host = (
            host
            or self._extract_host(
                effective_url
            )
            or self._extract_host(
                target
            )
        )

        effective_port = (
            port
            if port is not None
            else self._extract_port(
                effective_url
            )
        )

        effective_origin = (
            request_origin
            or self._extract_request_origin(
                response
            )
        )

        allow_origin = headers.get(
            "access-control-allow-origin"
        )

        allow_credentials = headers.get(
            "access-control-allow-credentials"
        )

        if not allow_origin:
            return []

        observations: list[CORSObservation] = []

        wildcard_credentials = (
            allow_origin.strip() == "*"
            and self._is_true_value(
                allow_credentials
            )
        )

        if wildcard_credentials:

            observations.append(
                self._wildcard_credentials_observation(
                    target=target,
                    host=effective_host,
                    port=effective_port,
                    url=effective_url,
                    allow_origin=allow_origin,
                    allow_credentials=allow_credentials,
                )
            )

        reflected_origin = (
            effective_origin is not None
            and self._origin_is_reflected(
                allow_origin,
                effective_origin,
            )
        )

        if reflected_origin:

            observations.append(
                self._reflected_origin_observation(
                    target=target,
                    host=effective_host,
                    port=effective_port,
                    url=effective_url,
                    request_origin=effective_origin,
                    allow_origin=allow_origin,
                    allow_credentials=allow_credentials,
                )
            )

        unsafe_origin = self._is_unsafe_origin(
            allow_origin
        )

        if (
            unsafe_origin
            and not wildcard_credentials
            and not reflected_origin
        ):
            observations.append(
                self._permissive_origin_observation(
                    target=target,
                    host=effective_host,
                    port=effective_port,
                    url=effective_url,
                    allow_origin=allow_origin,
                    allow_credentials=allow_credentials,
                )
            )

        return self._deduplicate(
            observations
        )

    ###########################################################################
    # Response extraction
    ###########################################################################

    @classmethod
    def _extract_headers(
        cls,
        response: Any,
    ) -> dict[str, str]:
        """
        Extract HTTP headers from common response representations.
        """

        if response is None:
            return {}

        if isinstance(response, Mapping):

            for key in (
                "headers",
                "response_headers",
                "http_headers",
            ):
                if key in response:
                    return _normalize_headers(
                        response.get(key)
                    )

            # A mapping containing actual HTTP header names.
            header_candidates = {
                str(key).lower()
                for key in response.keys()
            }

            if (
                "access-control-allow-origin"
                in header_candidates
                or "access-control-allow-credentials"
                in header_candidates
            ):
                return _normalize_headers(
                    response
                )

            return {}

        for attribute in (
            "headers",
            "response_headers",
        ):
            value = getattr(
                response,
                attribute,
                None,
            )

            if value is not None:
                return _normalize_headers(
                    value
                )

        return {}

    @staticmethod
    def _extract_url(
        response: Any,
    ) -> str | None:
        """Extract a response URL when available."""

        if isinstance(response, Mapping):

            for key in (
                "url",
                "response_url",
                "final_url",
            ):
                value = response.get(
                    key
                )

                if value:
                    return _text(value)

            return None

        for attribute in (
            "url",
            "response_url",
        ):
            value = getattr(
                response,
                attribute,
                None,
            )

            if value:
                return _text(value)

        return None

    @classmethod
    def _extract_request_origin(
        cls,
        response: Any,
    ) -> str | None:
        """
        Extract the request Origin header when the response evidence retains
        request headers.
        """

        if isinstance(response, Mapping):

            for key in (
                "request_headers",
                "requestHeaders",
            ):
                if key in response:
                    headers = _normalize_headers(
                        response.get(key)
                    )

                    return headers.get(
                        "origin"
                    )

            return None

        request_headers = getattr(
            response,
            "request_headers",
            None,
        )

        if request_headers is not None:
            headers = _normalize_headers(
                request_headers
            )

            return headers.get(
                "origin"
            )

        return None

    ###########################################################################
    # Detection
    ###########################################################################

    @staticmethod
    def _is_true_value(
        value: str | None,
    ) -> bool:
        """Determine whether a CORS boolean directive is explicitly true."""

        if not value:
            return False

        return value.strip().lower() == "true"

    @staticmethod
    def _origin_is_reflected(
        allow_origin: str,
        request_origin: str,
    ) -> bool:
        """
        Determine whether the response appears to reflect the supplied
        request Origin.
        """

        return (
            allow_origin.strip().lower()
            == request_origin.strip().lower()
            and request_origin.strip() != ""
        )

    @staticmethod
    def _is_unsafe_origin(
        allow_origin: str,
    ) -> bool:
        """
        Identify broadly permissive CORS origin policies.

        Wildcard origin is considered potentially risky, but it is only
        promoted to the strongest finding when credentialed access is also
        explicitly enabled.
        """

        normalized = allow_origin.strip().lower()

        if normalized == "*":
            return True

        # Multiple origins are not valid according to the normal CORS
        # response-header semantics and therefore warrant attention.
        if "," in normalized:
            return True

        return False

    ###########################################################################
    # Observation builders
    ###########################################################################

    @classmethod
    def _wildcard_credentials_observation(
        cls,
        *,
        target: str,
        host: str | None,
        port: int | None,
        url: str | None,
        allow_origin: str,
        allow_credentials: str | None,
    ) -> CORSObservation:
        """Build a credentialed wildcard CORS observation."""

        return CORSObservation(
            title="CORS Allows Wildcard Origin with Credentials",
            description=(
                "The HTTP response permits a wildcard cross-origin origin "
                "while also enabling credentialed CORS requests. This is an "
                "unsafe CORS configuration and should be reviewed for "
                "authentication or sensitive-data exposure."
            ),
            target=target,
            host=host,
            port=port,
            url=url,
            severity="High",
            confidence="High",
            evidence={
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
            },
            metadata={
                "issue": "wildcard_origin_with_credentials",
            },
        )

    @classmethod
    def _reflected_origin_observation(
        cls,
        *,
        target: str,
        host: str | None,
        port: int | None,
        url: str | None,
        request_origin: str,
        allow_origin: str,
        allow_credentials: str | None,
    ) -> CORSObservation:
        """Build a reflected-origin CORS observation."""

        credentials_enabled = cls._is_true_value(
            allow_credentials
        )

        if credentials_enabled:
            severity = "High"
            confidence = "High"
            title = (
                "CORS Reflects Origin with Credentials"
            )
            description = (
                "The response reflects the supplied Origin value in "
                "Access-Control-Allow-Origin while allowing credentials. "
                "This configuration can permit a malicious origin to make "
                "credentialed cross-origin requests if the origin is not "
                "properly validated."
            )
        else:
            severity = "Medium"
            confidence = "Medium"
            title = (
                "CORS Reflects Request Origin"
            )
            description = (
                "The response reflects the supplied Origin value in "
                "Access-Control-Allow-Origin. Dynamic origin reflection "
                "should be validated against an explicit trusted-origin "
                "allowlist."
            )

        return CORSObservation(
            title=title,
            description=description,
            target=target,
            host=host,
            port=port,
            url=url,
            severity=severity,
            confidence=confidence,
            evidence={
                "request_origin": request_origin,
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
            },
            metadata={
                "issue": "origin_reflection",
                "credentials_enabled": credentials_enabled,
            },
        )

    @classmethod
    def _permissive_origin_observation(
        cls,
        *,
        target: str,
        host: str | None,
        port: int | None,
        url: str | None,
        allow_origin: str,
        allow_credentials: str | None,
    ) -> CORSObservation:
        """Build a generic permissive-origin observation."""

        return CORSObservation(
            title="Permissive CORS Origin Configuration",
            description=(
                "The response exposes a broadly permissive "
                "Access-Control-Allow-Origin policy. The security impact "
                "depends on the resources exposed and whether credentials "
                "or sensitive data are involved."
            ),
            target=target,
            host=host,
            port=port,
            url=url,
            severity="Medium",
            confidence="Medium",
            evidence={
                "access_control_allow_origin": allow_origin,
                "access_control_allow_credentials": allow_credentials,
            },
            metadata={
                "issue": "permissive_origin",
            },
        )

    ###########################################################################
    # Target helpers
    ###########################################################################

    @staticmethod
    def _is_url(
        value: str | None,
    ) -> bool:
        """Return whether a value appears to be an HTTP(S) URL."""

        if not value:
            return False

        normalized = _text(value).lower()

        return (
            normalized.startswith("http://")
            or normalized.startswith("https://")
        )

    @classmethod
    def _extract_host(
        cls,
        target: str | None,
    ) -> str | None:
        """Extract hostname from an HTTP(S) URL."""

        if not cls._is_url(target):
            return None

        value = _text(target)

        without_scheme = value.split(
            "://",
            1,
        )[1]

        authority = without_scheme.split(
            "/",
            1,
        )[0]

        authority = authority.split(
            "?",
            1,
        )[0]

        authority = authority.split(
            "#",
            1,
        )[0]

        if "@" in authority:
            authority = authority.rsplit(
                "@",
                1,
            )[1]

        if authority.startswith("["):

            closing = authority.find("]")

            if closing != -1:
                return authority[
                    1:closing
                ]

        return authority.split(
            ":",
            1,
        )[0] or None

    @classmethod
    def _extract_port(
        cls,
        target: str | None,
    ) -> int | None:
        """Extract an explicitly specified HTTP(S) port."""

        if not cls._is_url(target):
            return None

        value = _text(target)

        authority = value.split(
            "://",
            1,
        )[1].split(
            "/",
            1,
        )[0]

        authority = authority.split(
            "?",
            1,
        )[0]

        authority = authority.split(
            "#",
            1,
        )[0]

        if "@" in authority:
            authority = authority.rsplit(
                "@",
                1,
            )[1]

        if authority.startswith("["):

            closing = authority.find("]")

            if closing != -1:

                remainder = authority[
                    closing + 1:
                ]

                if remainder.startswith(":"):

                    try:
                        return int(
                            remainder[1:]
                        )
                    except ValueError:
                        return None

                return None

        if ":" not in authority:
            return None

        port_text = authority.rsplit(
            ":",
            1,
        )[1]

        try:
            return int(
                port_text
            )
        except ValueError:
            return None

    ###########################################################################
    # Deduplication
    ###########################################################################

    @staticmethod
    def _deduplicate(
        observations: list[CORSObservation],
    ) -> list[CORSObservation]:
        """Remove duplicate observations generated from the same response."""

        unique: list[CORSObservation] = []
        seen: set[tuple[Any, ...]] = set()

        for observation in observations:

            evidence = observation.evidence

            fingerprint = (
                observation.category
                if hasattr(
                    observation,
                    "category",
                )
                else CATEGORY_CORS,
                observation.target,
                observation.url,
                observation.title,
                evidence.get(
                    "access_control_allow_origin"
                ),
                evidence.get(
                    "access_control_allow_credentials"
                ),
                evidence.get(
                    "request_origin"
                ),
            )

            if fingerprint in seen:
                continue

            seen.add(
                fingerprint
            )
            unique.append(
                observation
            )

        return unique


###############################################################################
# Compatibility aliases
###############################################################################


Analyzer = CORSAnalyzer


###############################################################################
# Public API
###############################################################################


__all__ = [
    "CORSAnalyzer",
    "CORSObservation",
    "Analyzer",
    "ANALYZER_NAME",
    "CATEGORY_CORS",
    "DETECTION_METHOD",
]
