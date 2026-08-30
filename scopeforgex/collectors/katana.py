"""
ScopeForgeX Katana Collector
============================

Parses Katana crawler output into structured ScopeForgeX observations.

Katana is responsible for web crawling and endpoint discovery.

Primary observations:

    URL
    ENDPOINT
    PARAMETER
    FORM
    RESOURCE

Architecture
------------

Katana
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
KatanaCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes Katana.
- The collector never constructs Katana commands.
- Raw Katana output remains preserved in the ExecutionResult artifacts.
- Plain-text and JSONL-style Katana output are supported.
- Duplicate URLs are removed deterministically.
- Query parameters are represented separately when present.
- Static resources are classified as RESOURCE observations.
- The collector does not assign final severity or risk.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlparse

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "katana"

OBSERVATION_URL = "URL"
OBSERVATION_ENDPOINT = "ENDPOINT"
OBSERVATION_PARAMETER = "PARAMETER"
OBSERVATION_FORM = "FORM"
OBSERVATION_RESOURCE = "RESOURCE"


###############################################################################
# Collector
###############################################################################


class KatanaCollector(CollectorBase):
    """
    Collect structured web-crawling observations from Katana output.

    Katana normally emits discovered URLs as newline-delimited output.

    The collector also accepts JSONL-style records when the execution artifact
    contains structured objects with a URL-like field.
    """

    name = "katana"
    tool = "katana"

    description = (
        "Parses Katana crawler output into URL, endpoint, parameter, "
        "form and resource observations."
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
        Parse Katana output into structured observations.

        The parser checks:

        1. ExecutionResult stdout
        2. ExecutionResult artifacts

        Artifact content is preferred when available because artifacts are
        persistent evidence associated with the execution.
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

        seen_urls: set[str] = set()
        seen_parameters: set[tuple[str, str]] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed = self._parse_record(
                    record
                )

                if parsed is None:
                    continue

                url = parsed["url"]

                normalized_url = self._normalize_url(
                    url
                )

                if not normalized_url:
                    continue

                if normalized_url in seen_urls:
                    continue

                seen_urls.add(
                    normalized_url
                )

                url_type = self._classify_url(
                    normalized_url
                )

                observations.append(
                    CollectorObservation(
                        observation_type=OBSERVATION_URL,
                        value=normalized_url,
                        target=target,
                        host=self._extract_host(
                            normalized_url
                        ),
                        port=self._extract_port(
                            normalized_url
                        ),
                        url=normalized_url,
                        evidence=record,
                        source_tool=TOOL_NAME,
                        detection_method=(
                            "Katana web crawler"
                        ),
                        confidence="informational",
                        metadata={
                            "source": source,
                            "url_type": url_type,
                        },
                    )
                )

                if url_type == "endpoint":
                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_ENDPOINT
                            ),
                            value=normalized_url,
                            target=target,
                            host=self._extract_host(
                                normalized_url
                            ),
                            port=self._extract_port(
                                normalized_url
                            ),
                            url=normalized_url,
                            evidence=record,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "Katana endpoint discovery"
                            ),
                            confidence="informational",
                            metadata={
                                "source": source,
                            },
                        )
                    )

                elif url_type == "resource":
                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_RESOURCE
                            ),
                            value=normalized_url,
                            target=target,
                            host=self._extract_host(
                                normalized_url
                            ),
                            port=self._extract_port(
                                normalized_url
                            ),
                            url=normalized_url,
                            evidence=record,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "Katana resource discovery"
                            ),
                            confidence="informational",
                            metadata={
                                "source": source,
                                "resource_type": (
                                    self._resource_type(
                                        normalized_url
                                    )
                                ),
                            },
                        )
                    )

                for parameter in self._extract_parameters(
                    normalized_url
                ):

                    key = (
                        normalized_url,
                        parameter,
                    )

                    if key in seen_parameters:
                        continue

                    seen_parameters.add(
                        key
                    )

                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_PARAMETER
                            ),
                            value=parameter,
                            target=target,
                            host=self._extract_host(
                                normalized_url
                            ),
                            port=self._extract_port(
                                normalized_url
                            ),
                            url=normalized_url,
                            parameter=parameter,
                            evidence=record,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "Katana URL parameter discovery"
                            ),
                            confidence="informational",
                            metadata={
                                "source": source,
                            },
                        )
                    )

                form = self._extract_form(
                    parsed
                )

                if form is not None:
                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_FORM
                            ),
                            value=form,
                            target=target,
                            host=self._extract_host(
                                normalized_url
                            ),
                            port=self._extract_port(
                                normalized_url
                            ),
                            url=normalized_url,
                            evidence=record,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "Katana form discovery"
                            ),
                            confidence="informational",
                            metadata={
                                "source": source,
                            },
                        )
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
        Return available Katana evidence as labelled text.

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
        Resolve an artifact into a filesystem path.
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
        Convert raw content into logical records.

        Katana commonly emits one URL per line.

        JSON objects are retained when a line is valid JSON so that structured
        fields can be inspected before falling back to plain text handling.
        """

        records: list[str | dict[str, Any]] = []

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith(
                "{"
            ) and stripped.endswith(
                "}"
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
        Normalize a raw Katana record into a small internal representation.
        """

        if isinstance(
            record,
            str,
        ):
            url = record.strip()

            if not self._looks_like_url(
                url
            ):
                return None

            return {
                "url": url,
                "form": None,
                "metadata": {},
            }

        url = self._extract_url_from_mapping(
            record
        )

        if not url:
            return None

        return {
            "url": url,
            "form": self._extract_form_from_mapping(
                record
            ),
            "metadata": dict(
                record
            ),
        }

    @staticmethod
    def _extract_url_from_mapping(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a URL from a structured record.
        """

        candidates = (
            "request",
            "url",
            "endpoint",
            "input",
            "link",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                candidate = value.strip()

                if (
                    candidate.startswith(
                        "http://"
                    )
                    or candidate.startswith(
                        "https://"
                    )
                ):
                    return candidate

        return None

    ###########################################################################
    # URL Classification
    ###########################################################################

    @staticmethod
    def _looks_like_url(
        value: str,
    ) -> bool:
        """
        Return whether a value appears to be an HTTP(S) URL.
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
        Normalize a discovered URL without destroying meaningful path/query
        information.
        """

        url = str(
            value
        ).strip()

        if not cls._looks_like_url(
            url
        ):
            return ""

        parsed = urlparse(
            url
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
    def _classify_url(
        url: str,
    ) -> str:
        """
        Classify a URL as an endpoint or static resource.
        """

        path = (
            urlparse(
                url
            ).path
            or "/"
        ).lower()

        resource_extensions = {
            ".css",
            ".js",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".ico",
            ".webp",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".map",
            ".pdf",
            ".zip",
            ".tar",
            ".gz",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".webm",
            ".xml",
            ".txt",
        }

        for extension in resource_extensions:

            if path.endswith(
                extension
            ):
                return "resource"

        return "endpoint"

    ###########################################################################
    # Parameter Extraction
    ###########################################################################

    @staticmethod
    def _extract_parameters(
        url: str,
    ) -> list[str]:
        """
        Return unique query parameter names from a URL.
        """

        parsed = urlparse(
            url
        )

        if not parsed.query:
            return []

        parameters: list[str] = []

        for name, _ in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        ):

            normalized = name.strip()

            if (
                normalized
                and normalized not in parameters
            ):
                parameters.append(
                    normalized
                )

        return parameters

    ###########################################################################
    # Form Extraction
    ###########################################################################

    @staticmethod
    def _extract_form_from_mapping(
        record: Mapping[str, Any],
    ) -> Any:
        """
        Extract form-related information from a structured record when
        available.
        """

        for key in (
            "form",
            "forms",
            "method",
        ):

            if key in record:
                value = record.get(
                    key
                )

                if value not in (
                    None,
                    "",
                    [],
                    {},
                ):
                    return {
                        key: value
                    }

        return None

    @staticmethod
    def _extract_form(
        parsed: Mapping[str, Any],
    ) -> Any:
        """
        Return structured form information from a parsed record.
        """

        form = parsed.get(
            "form"
        )

        if form is None:
            metadata = parsed.get(
                "metadata",
                {},
            )

            if isinstance(
                metadata,
                Mapping,
            ):
                form = (
                    KatanaCollector
                    ._extract_form_from_mapping(
                        metadata
                    )
                )

        return form

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
        url: str,
    ) -> str | None:
        """
        Extract the hostname from a URL.
        """

        try:
            hostname = urlparse(
                url
            ).hostname

        except ValueError:
            return None

        return hostname

    @staticmethod
    def _extract_port(
        url: str,
    ) -> int | None:
        """
        Extract an explicit or effective port from a URL.
        """

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

    @staticmethod
    def _resource_type(
        url: str,
    ) -> str:
        """
        Identify the approximate static resource type.
        """

        path = (
            urlparse(
                url
            ).path
            or ""
        ).lower()

        resource_types = {
            ".js": "javascript",
            ".css": "stylesheet",
            ".json": "json",
            ".xml": "xml",
            ".map": "source_map",
            ".pdf": "document",
            ".txt": "text",
            ".png": "image",
            ".jpg": "image",
            ".jpeg": "image",
            ".gif": "image",
            ".svg": "image",
            ".webp": "image",
            ".woff": "font",
            ".woff2": "font",
            ".ttf": "font",
            ".eot": "font",
        }

        for extension, resource_type in (
            resource_types.items()
        ):

            if path.endswith(
                extension
            ):
                return resource_type

        return "resource"


###############################################################################
# Public API
###############################################################################


__all__ = [
    "KatanaCollector",
]
