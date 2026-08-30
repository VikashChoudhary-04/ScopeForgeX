"""
ScopeForgeX JSLuice Collector
=============================

Parses JSLuice JavaScript analysis output into structured ScopeForgeX
observations.

JSLuice is responsible for JavaScript attack-surface analysis.

Primary observations:

    JS_ENDPOINT
    JS_URL
    SECRET_CANDIDATE
    API_REFERENCE

Architecture
------------

JSLuice
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
JSLuiceCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes JSLuice.
- The collector never constructs JSLuice commands.
- Raw JSLuice output remains preserved in the ExecutionResult artifacts.
- Plain-text and JSONL-style output are supported.
- Structured records are normalized without discarding useful evidence.
- URLs and endpoint references are classified deterministically.
- Potential secrets are observations, not automatically confirmed credentials.
- API references are represented separately from generic JavaScript URLs.
- The collector does not assign final severity or risk.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "jsluice"

OBSERVATION_JS_ENDPOINT = "JS_ENDPOINT"
OBSERVATION_JS_URL = "JS_URL"
OBSERVATION_SECRET_CANDIDATE = "SECRET_CANDIDATE"
OBSERVATION_API_REFERENCE = "API_REFERENCE"


###############################################################################
# Collector
###############################################################################


class JSLuiceCollector(CollectorBase):
    """
    Collect structured JavaScript attack-surface observations from JSLuice
    output.

    JSLuice output can vary depending on the selected analysis mode. The
    collector therefore accepts both plain-text values and JSONL-style
    records containing URLs, endpoints, secrets or API references.
    """

    name = "jsluice"
    tool = "jsluice"

    description = (
        "Parses JSLuice JavaScript analysis output into JS endpoint, "
        "JS URL, secret candidate and API reference observations."
    )

    supported_input_types = (
        "execution_result",
        "raw_file",
        "text",
    )

    ###########################################################################
    # Input Validation
    ###########################################################################

    def validate_input(
        self,
        execution_result: Any,
    ) -> None:
        """
        Validate the supplied execution result.
        """

        super().validate_input(
            execution_result
        )

    ###########################################################################
    # Parsing
    ###########################################################################

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse JSLuice output into structured observations.

        The parser examines stdout and available execution artifacts. Each
        logical record can produce multiple observations when the record
        contains multiple distinct JavaScript attack-surface indicators.
        """

        target = self._resolve_target(
            execution_result,
            ctx,
        )

        contents = self._collect_input_contents(
            execution_result,
            ctx,
        )

        if not contents:
            return []

        observations: list[CollectorObservation] = []

        seen: set[tuple[str, str, str | None]] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):
                parsed = self._parse_record(
                    record
                )

                if parsed is None:
                    continue

                evidence = record

                for item in self._extract_observations(
                    parsed
                ):
                    observation_type = item[
                        "observation_type"
                    ]

                    value = item[
                        "value"
                    ]

                    url = item.get(
                        "url"
                    )

                    key = (
                        observation_type,
                        value,
                        url,
                    )

                    if key in seen:
                        continue

                    seen.add(
                        key
                    )

                    observation = (
                        self._build_observation(
                            observation_type=(
                                observation_type
                            ),
                            value=value,
                            target=target,
                            url=url,
                            evidence=evidence,
                            source=source,
                            metadata=item.get(
                                "metadata",
                                {},
                            ),
                        )
                    )

                    observations.append(
                        observation
                    )

        return observations

    ###########################################################################
    # Input Collection
    ###########################################################################

    def _collect_input_contents(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[tuple[str, str]]:
        """
        Return available JSLuice evidence as labelled text.

        Duplicate artifact paths are processed only once.
        """

        contents: list[tuple[str, str]] = []

        stdout = getattr(
            execution_result,
            "stdout",
            "",
        )

        if stdout:
            contents.append(
                (
                    "stdout",
                    str(stdout),
                )
            )

        artifacts = ctx.get(
            "artifacts",
            [],
        )

        seen_paths: set[str] = set()

        for artifact in artifacts:

            path = self._artifact_path(
                artifact
            )

            if path is None:
                continue

            normalized_path = str(
                path
            )

            if normalized_path in seen_paths:
                continue

            seen_paths.add(
                normalized_path
            )

            content = read_text_file(
                path
            )

            if content:
                contents.append(
                    (
                        normalized_path,
                        content,
                    )
                )

        return contents

    @staticmethod
    def _artifact_path(
        artifact: Any,
    ) -> Path | None:
        """
        Resolve an execution artifact into a filesystem path.
        """

        if artifact is None:
            return None

        if hasattr(
            artifact,
            "path",
        ):
            value = artifact.path

        else:
            value = artifact

        if value is None:
            return None

        return Path(
            str(value)
        )

    ###########################################################################
    # Record Parsing
    ###########################################################################

    def _iter_records(
        self,
        content: str,
    ) -> list[str | dict[str, Any]]:
        """
        Convert raw JSLuice output into logical records.

        JSON objects are retained so structured fields can be inspected.
        Non-JSON lines remain available as plain-text records.
        """

        records: list[str | dict[str, Any]] = []

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            if (
                stripped.startswith("{")
                and stripped.endswith("}")
            ):
                try:
                    value = json.loads(
                        stripped
                    )

                except json.JSONDecodeError:
                    value = None

                if isinstance(
                    value,
                    dict,
                ):
                    records.append(
                        value
                    )
                    continue

            records.append(
                stripped
            )

        return records

    def _parse_record(
        self,
        record: str | dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Normalize a raw JSLuice record into an internal representation.
        """

        if isinstance(
            record,
            str,
        ):
            value = record.strip()

            if not value:
                return None

            return {
                "raw": value,
                "url": (
                    value
                    if self._looks_like_url(
                        value
                    )
                    else None
                ),
                "endpoint": (
                    value
                    if self._looks_like_endpoint(
                        value
                    )
                    else None
                ),
                "secret": None,
                "api_reference": (
                    value
                    if self._looks_like_api_reference(
                        value
                    )
                    else None
                ),
                "metadata": {},
            }

        normalized = dict(
            record
        )

        url = self._extract_url(
            normalized
        )

        endpoint = self._extract_endpoint(
            normalized
        )

        secret = self._extract_secret(
            normalized
        )

        api_reference = (
            self._extract_api_reference(
                normalized
            )
        )

        if (
            url is None
            and endpoint is None
            and secret is None
            and api_reference is None
        ):
            return None

        return {
            "raw": normalized,
            "url": url,
            "endpoint": endpoint,
            "secret": secret,
            "api_reference": api_reference,
            "metadata": normalized,
        }

    ###########################################################################
    # Observation Extraction
    ###########################################################################

    def _extract_observations(
        self,
        parsed: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Convert a parsed record into normalized observation specifications.
        """

        observations: list[dict[str, Any]] = []

        url = parsed.get(
            "url"
        )

        endpoint = parsed.get(
            "endpoint"
        )

        secret = parsed.get(
            "secret"
        )

        api_reference = parsed.get(
            "api_reference"
        )

        if isinstance(
            url,
            str,
        ) and url:

            normalized_url = (
                self._normalize_url(
                    url
                )
            )

            if normalized_url:

                if self._looks_like_api_reference(
                    normalized_url
                ):
                    observations.append(
                        {
                            "observation_type": (
                                OBSERVATION_API_REFERENCE
                            ),
                            "value": normalized_url,
                            "url": normalized_url,
                            "metadata": {
                                "classification": "api",
                            },
                        }
                    )

                elif self._looks_like_js_url(
                    normalized_url
                ):
                    observations.append(
                        {
                            "observation_type": (
                                OBSERVATION_JS_URL
                            ),
                            "value": normalized_url,
                            "url": normalized_url,
                            "metadata": {
                                "classification": (
                                    "javascript"
                                ),
                            },
                        }
                    )

                else:
                    observations.append(
                        {
                            "observation_type": (
                                OBSERVATION_JS_ENDPOINT
                            ),
                            "value": normalized_url,
                            "url": normalized_url,
                            "metadata": {
                                "classification": (
                                    "endpoint"
                                ),
                            },
                        }
                    )

        if isinstance(
            endpoint,
            str,
        ) and endpoint:

            normalized_endpoint = (
                self._normalize_reference(
                    endpoint
                )
            )

            if normalized_endpoint:
                observations.append(
                    {
                        "observation_type": (
                            OBSERVATION_JS_ENDPOINT
                        ),
                        "value": normalized_endpoint,
                        "url": self._related_url(
                            normalized_endpoint,
                            url,
                        ),
                        "metadata": {
                            "classification": (
                                "endpoint"
                            ),
                        },
                    }
                )

        if isinstance(
            secret,
            str,
        ) and secret:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SECRET_CANDIDATE
                    ),
                    "value": secret,
                    "url": (
                        self._normalize_url(
                            url
                        )
                        if isinstance(
                            url,
                            str,
                        )
                        else None
                    ),
                    "metadata": {
                        "classification": (
                            "potential_secret"
                        ),
                    },
                }
            )

        if isinstance(
            api_reference,
            str,
        ) and api_reference:

            normalized_api = (
                self._normalize_reference(
                    api_reference
                )
            )

            if normalized_api:
                observations.append(
                    {
                        "observation_type": (
                            OBSERVATION_API_REFERENCE
                        ),
                        "value": normalized_api,
                        "url": (
                            self._normalize_url(
                                url
                            )
                            if isinstance(
                                url,
                                str,
                            )
                            else None
                        ),
                        "metadata": {
                            "classification": "api",
                        },
                    }
                )

        return observations

    def _build_observation(
        self,
        *,
        observation_type: str,
        value: str,
        target: str | None,
        url: str | None,
        evidence: Any,
        source: str,
        metadata: Mapping[str, Any],
    ) -> CollectorObservation:
        """
        Construct a CollectorObservation from a normalized observation.
        """

        host = self._extract_host(
            url
        ) if url else None

        port = self._extract_port(
            url
        ) if url else None

        detection_methods = {
            OBSERVATION_JS_ENDPOINT: (
                "JSLuice JavaScript endpoint discovery"
            ),
            OBSERVATION_JS_URL: (
                "JSLuice JavaScript URL discovery"
            ),
            OBSERVATION_SECRET_CANDIDATE: (
                "JSLuice potential secret detection"
            ),
            OBSERVATION_API_REFERENCE: (
                "JSLuice API reference discovery"
            ),
        }

        return CollectorObservation(
            observation_type=observation_type,
            value=value,
            target=target,
            host=host,
            port=port,
            url=url,
            evidence=evidence,
            source_tool=TOOL_NAME,
            detection_method=(
                detection_methods.get(
                    observation_type,
                    "JSLuice JavaScript analysis",
                )
            ),
            confidence="informational",
            metadata={
                "source": source,
                **dict(
                    metadata
                ),
            },
        )

    ###########################################################################
    # Structured Field Extraction
    ###########################################################################

    @staticmethod
    def _extract_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a URL-like field from a structured JSLuice record.
        """

        candidates = (
            "url",
            "URL",
            "source",
            "src",
            "input",
            "page",
            "script",
            "script_url",
            "javascript",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                value = value.strip()

                if value and (
                    value.startswith(
                        "http://"
                    )
                    or value.startswith(
                        "https://"
                    )
                ):
                    return value

        return None

    @staticmethod
    def _extract_endpoint(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an endpoint-like field from a structured record.
        """

        candidates = (
            "endpoint",
            "path",
            "route",
            "uri",
            "link",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                value = value.strip()

                if value:
                    return value

        return None

    @staticmethod
    def _extract_secret(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a potential secret from a structured record.

        The value is preserved as supplied by the parser. This collector does
        not attempt to determine whether a candidate is actually valid.
        """

        candidates = (
            "secret",
            "secrets",
            "secret_candidate",
            "secret_candidate_value",
            "value",
            "match",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                if (
                    "secret" in key.lower()
                    or "match" in key.lower()
                ):
                    return value.strip()

        return None

    @staticmethod
    def _extract_api_reference(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an API reference from a structured record.
        """

        candidates = (
            "api",
            "api_url",
            "api_endpoint",
            "api_reference",
            "api_route",
            "route",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip()

        return None

    ###########################################################################
    # URL / Reference Helpers
    ###########################################################################

    @staticmethod
    def _looks_like_url(
        value: str,
    ) -> bool:
        """
        Return whether a value is an HTTP(S) URL.
        """

        return (
            value.startswith(
                "http://"
            )
            or value.startswith(
                "https://"
            )
        )

    @classmethod
    def _normalize_url(
        cls,
        value: str,
    ) -> str:
        """
        Normalize an HTTP(S) URL while preserving path and query information.
        """

        value = str(
            value
        ).strip()

        if not cls._looks_like_url(
            value
        ):
            return ""

        parsed = urlparse(
            value
        )

        if not parsed.scheme or not parsed.netloc:
            return ""

        scheme = parsed.scheme.lower()
        hostname = (
            parsed.hostname or ""
        ).lower()

        if not hostname:
            return ""

        try:
            port = parsed.port

        except ValueError:
            return ""

        netloc = hostname

        if port is not None:
            default_port = (
                80
                if scheme == "http"
                else 443
            )

            if port != default_port:
                netloc = (
                    f"{hostname}:{port}"
                )

        path = (
            parsed.path
            or "/"
        )

        normalized = (
            f"{scheme}://"
            f"{netloc}"
            f"{path}"
        )

        if parsed.params:
            normalized += (
                f";{parsed.params}"
            )

        if parsed.query:
            normalized += (
                f"?{parsed.query}"
            )

        if parsed.fragment:
            normalized += (
                f"#{parsed.fragment}"
            )

        return normalized

    @staticmethod
    def _normalize_reference(
        value: str,
    ) -> str:
        """
        Normalize a JavaScript endpoint/reference without requiring it to be a
        fully-qualified URL.
        """

        value = str(
            value
        ).strip()

        if not value:
            return ""

        while value.startswith(
            "./"
        ):
            value = value[2:]

        return value

    @staticmethod
    def _looks_like_endpoint(
        value: str,
    ) -> bool:
        """
        Determine whether plain text appears to represent an endpoint.
        """

        if not value:
            return False

        if value.startswith(
            (
                "/",
                "./",
                "../",
            )
        ):
            return True

        return (
            value.startswith(
                "api/"
            )
            or value.startswith(
                "v1/"
            )
            or value.startswith(
                "v2/"
            )
            or value.startswith(
                "v3/"
            )
        )

    @staticmethod
    def _looks_like_js_url(
        url: str,
    ) -> bool:
        """
        Determine whether a URL points to a JavaScript resource.
        """

        path = (
            urlparse(
                url
            ).path
            or ""
        ).lower()

        return (
            path.endswith(
                ".js"
            )
            or path.endswith(
                ".mjs"
            )
        )

    @staticmethod
    def _looks_like_api_reference(
        value: str,
    ) -> bool:
        """
        Determine whether a URL/reference appears API-related.
        """

        normalized = str(
            value
        ).lower()

        if (
            "/api/" in normalized
            or normalized.startswith(
                "api/"
            )
            or normalized.startswith(
                "/api"
            )
        ):
            return True

        api_versions = (
            "/v1/",
            "/v2/",
            "/v3/",
            "/v4/",
            "/v5/",
            "/graphql",
            "/rest/",
        )

        return any(
            marker in normalized
            for marker in api_versions
        )

    @staticmethod
    def _related_url(
        reference: str,
        source_url: Any,
    ) -> str | None:
        """
        Associate a relative JavaScript reference with its source URL when the
        source URL is available.

        The collector deliberately does not perform network requests.
        """

        if not isinstance(
            source_url,
            str,
        ):
            return None

        normalized_source = (
            JSLuiceCollector._normalize_url(
                source_url
            )
        )

        return normalized_source or None

    ###########################################################################
    # Target / Host Helpers
    ###########################################################################

    @staticmethod
    def _resolve_target(
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> str | None:
        """
        Resolve the assessment target from collector context or execution
        metadata.
        """

        target = ctx.get(
            "target"
        )

        if target:
            return str(
                target
            ).strip()

        metadata = getattr(
            execution_result,
            "metadata",
            {},
        )

        if isinstance(
            metadata,
            Mapping,
        ):
            target = metadata.get(
                "target"
            )

            if target:
                return str(
                    target
                ).strip()

        return None

    @staticmethod
    def _extract_host(
        url: str | None,
    ) -> str | None:
        """
        Extract the hostname from a URL.
        """

        if not url:
            return None

        try:
            return urlparse(
                url
            ).hostname

        except ValueError:
            return None

    @staticmethod
    def _extract_port(
        url: str | None,
    ) -> int | None:
        """
        Extract an explicit or effective HTTP(S) port.
        """

        if not url:
            return None

        try:
            parsed = urlparse(
                url
            )

            if parsed.port is not None:
                return parsed.port

            if parsed.scheme.lower() == "http":
                return 80

            if parsed.scheme.lower() == "https":
                return 443

        except ValueError:
            return None

        return None


###############################################################################
# Public API
###############################################################################


__all__ = [
    "JSLuiceCollector",
]
