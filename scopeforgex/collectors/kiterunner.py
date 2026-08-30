"""
ScopeForgeX Kiterunner Collector
================================

Parses Kiterunner API discovery output into structured ScopeForgeX
observations.

Kiterunner is responsible for discovering API routes and endpoints from
API route dictionaries.

Primary observations:

    API_ENDPOINT
    API_ROUTE

Architecture
------------

Kiterunner
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
KiterunnerCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes Kiterunner.
- The collector never constructs Kiterunner commands.
- Raw Kiterunner output remains preserved in the ExecutionResult artifacts.
- Common text output and JSON/JSONL-style output are supported.
- Duplicate routes are removed deterministically.
- HTTP methods are preserved when available.
- Status codes, content lengths and other discovery metadata are preserved.
- The collector does not assign final severity or risk.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
import re
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


TOOL_NAME = "kiterunner"

OBSERVATION_API_ENDPOINT = "API_ENDPOINT"
OBSERVATION_API_ROUTE = "API_ROUTE"


###############################################################################
# Collector
###############################################################################


class KiterunnerCollector(CollectorBase):
    """
    Collect structured API observations from Kiterunner output.

    Kiterunner output can vary depending on the selected command and wordlist.
    The collector therefore accepts structured JSON records as well as common
    human-readable route output.
    """

    name = "kiterunner"
    tool = "kiterunner"

    description = (
        "Parses Kiterunner API discovery output into API endpoint and "
        "API route observations."
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
        Parse Kiterunner output into structured API observations.

        The parser checks:

        1. ExecutionResult stdout
        2. ExecutionResult artifacts

        Artifact content is retained as persistent evidence associated with
        the execution.
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

        seen: set[
            tuple[
                str,
                str,
                str | None,
                int | None,
            ]
        ] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed_records = self._parse_record(
                    record
                )

                for parsed in parsed_records:

                    url = self._normalize_url(
                        parsed.get(
                            "url"
                        )
                    )

                    route = self._normalize_route(
                        parsed.get(
                            "route"
                        )
                    )

                    if not url and route:
                        url = self._join_target_route(
                            target,
                            route,
                        )

                    if not url and not route:
                        continue

                    if not route and url:
                        route = self._extract_route(
                            url
                        )

                    method = self._normalize_method(
                        parsed.get(
                            "method"
                        )
                    )

                    status_code = self._normalize_status_code(
                        parsed.get(
                            "status_code"
                        )
                    )

                    content_length = self._normalize_integer(
                        parsed.get(
                            "content_length"
                        )
                    )

                    effective_value = (
                        url
                        or route
                    )

                    key = (
                        method or "",
                        effective_value.lower(),
                        route.lower()
                        if route
                        else "",
                        status_code,
                    )

                    if key in seen:
                        continue

                    seen.add(
                        key
                    )

                    evidence = {
                        "record": record,
                    }

                    if method:
                        evidence[
                            "method"
                        ] = method

                    if status_code is not None:
                        evidence[
                            "status_code"
                        ] = status_code

                    if content_length is not None:
                        evidence[
                            "content_length"
                        ] = content_length

                    if route:
                        evidence[
                            "route"
                        ] = route

                    if url:
                        evidence[
                            "url"
                        ] = url

                    metadata = {
                        "source": source,
                        "api_route": route,
                        "http_method": method,
                    }

                    if status_code is not None:
                        metadata[
                            "status_code"
                        ] = status_code

                    if content_length is not None:
                        metadata[
                            "content_length"
                        ] = content_length

                    host = self._extract_host(
                        url
                    )

                    port = self._extract_port(
                        url
                    )

                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_API_ENDPOINT
                            ),
                            value=effective_value,
                            target=target,
                            host=host,
                            port=port,
                            url=url,
                            evidence=evidence,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "Kiterunner API route discovery"
                            ),
                            confidence="informational",
                            metadata=metadata,
                        )
                    )

                    if route:
                        observations.append(
                            CollectorObservation(
                                observation_type=(
                                    OBSERVATION_API_ROUTE
                                ),
                                value=route,
                                target=target,
                                host=host,
                                port=port,
                                url=url,
                                evidence=evidence,
                                source_tool=TOOL_NAME,
                                detection_method=(
                                    "Kiterunner API route discovery"
                                ),
                                confidence="informational",
                                metadata=metadata,
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
        Return available Kiterunner evidence as labelled text.

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
    ) -> list[Any]:
        """
        Convert raw Kiterunner output into logical records.

        Supports:

        - JSON objects
        - JSON arrays
        - JSONL objects
        - Plain-text route lines
        """

        stripped_content = content.strip()

        if not stripped_content:
            return []

        parsed_json = self._try_parse_json(
            stripped_content
        )

        if parsed_json is not None:

            if isinstance(
                parsed_json,
                list,
            ):
                return list(
                    parsed_json
                )

            return [
                parsed_json
            ]

        records: list[Any] = []

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            parsed_line = self._try_parse_json(
                stripped
            )

            if parsed_line is not None:

                if isinstance(
                    parsed_line,
                    list,
                ):
                    records.extend(
                        parsed_line
                    )

                else:
                    records.append(
                        parsed_line
                    )

                continue

            records.append(
                stripped
            )

        return records

    @staticmethod
    def _try_parse_json(
        value: str,
    ) -> Any | None:
        """
        Attempt to decode a JSON value.
        """

        try:
            return json.loads(
                value
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):
            return None

    def _parse_record(
        self,
        record: Any,
    ) -> list[dict[str, Any]]:
        """
        Parse one Kiterunner record.

        Structured records are preferred. Plain-text records are parsed using
        conservative URL and HTTP-method patterns.
        """

        if isinstance(
            record,
            Mapping,
        ):
            parsed = self._parse_mapping_record(
                record
            )

            return (
                [parsed]
                if parsed is not None
                else []
            )

        if isinstance(
            record,
            str,
        ):
            parsed = self._parse_text_record(
                record
            )

            return (
                [parsed]
                if parsed is not None
                else []
            )

        return []

    def _parse_mapping_record(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """
        Parse a structured Kiterunner result.
        """

        url = self._extract_url(
            record
        )

        route = self._extract_route_from_mapping(
            record
        )

        if not url and not route:
            return None

        method = self._extract_method(
            record
        )

        status_code = self._extract_status_code(
            record
        )

        content_length = self._extract_content_length(
            record
        )

        return {
            "url": url,
            "route": route,
            "method": method,
            "status_code": status_code,
            "content_length": content_length,
        }

    def _parse_text_record(
        self,
        record: str,
    ) -> dict[str, Any] | None:
        """
        Parse common human-readable Kiterunner output.

        The parser accepts lines containing either:

            GET /api/users

        or:

            GET https://example.com/api/users 200

        or a bare URL/path containing an HTTP route.
        """

        value = record.strip()

        if not value:
            return None

        method_match = re.search(
            r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE)\b",
            value,
            re.IGNORECASE,
        )

        method = (
            method_match.group(
                1
            ).upper()
            if method_match
            else None
        )

        url_match = re.search(
            r"https?://[^\s\]\[\"']+",
            value,
            re.IGNORECASE,
        )

        url = (
            url_match.group(
                0
            )
            if url_match
            else None
        )

        route = None

        if url:
            route = self._extract_route(
                url
            )

        else:
            route_match = re.search(
                r"(?<!\w)(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%{}\-]+)",
                value,
            )

            if route_match:
                route = route_match.group(
                    1
                )

        if not url and not route:
            return None

        status_code = self._extract_status_from_text(
            value
        )

        content_length = self._extract_content_length_from_text(
            value
        )

        return {
            "url": url,
            "route": route,
            "method": method,
            "status_code": status_code,
            "content_length": content_length,
        }

    ###########################################################################
    # Structured Field Extraction
    ###########################################################################

    @staticmethod
    def _extract_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an absolute URL from a structured record.
        """

        for key in (
            "url",
            "target",
            "input",
            "endpoint",
            "request",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                candidate = value.strip()

                match = re.search(
                    r"https?://[^\s\"']+",
                    candidate,
                    re.IGNORECASE,
                )

                if match:
                    return match.group(
                        0
                    )

        return None

    @staticmethod
    def _extract_route_from_mapping(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an API route/path from a structured record.
        """

        for key in (
            "route",
            "path",
            "endpoint",
            "uri",
            "request",
        ):

            value = record.get(
                key
            )

            if not isinstance(
                value,
                str,
            ):
                continue

            candidate = value.strip()

            if candidate.startswith(
                "/"
            ):
                return candidate

            match = re.search(
                r"https?://[^/\s]+(/[^\s\"']*)",
                candidate,
                re.IGNORECASE,
            )

            if match:
                return match.group(
                    1
                )

        return None

    @staticmethod
    def _extract_method(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an HTTP method from a structured record.
        """

        for key in (
            "method",
            "http_method",
            "verb",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):
                method = value.strip().upper()

                if method in {
                    "GET",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                    "OPTIONS",
                    "HEAD",
                    "TRACE",
                }:
                    return method

        request = record.get(
            "request"
        )

        if isinstance(
            request,
            str,
        ):
            match = re.search(
                r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE)\b",
                request,
                re.IGNORECASE,
            )

            if match:
                return match.group(
                    1
                ).upper()

        return None

    @staticmethod
    def _extract_status_code(
        record: Mapping[str, Any],
    ) -> int | None:
        """
        Extract an HTTP status code from a structured record.
        """

        for key in (
            "status",
            "status_code",
            "code",
            "response_code",
        ):

            value = record.get(
                key
            )

            status = KiterunnerCollector._normalize_status_code(
                value
            )

            if status is not None:
                return status

        return None

    @staticmethod
    def _extract_content_length(
        record: Mapping[str, Any],
    ) -> int | None:
        """
        Extract a response/content length from a structured record.
        """

        for key in (
            "content_length",
            "length",
            "size",
            "response_length",
        ):

            value = record.get(
                key
            )

            normalized = (
                KiterunnerCollector._normalize_integer(
                    value
                )
            )

            if normalized is not None:
                return normalized

        return None

    @staticmethod
    def _extract_status_from_text(
        value: str,
    ) -> int | None:
        """
        Extract a plausible HTTP status code from text.
        """

        for match in re.finditer(
            r"(?<!\d)([1-5]\d{2})(?!\d)",
            value,
        ):

            status = int(
                match.group(
                    1
                )
            )

            if 100 <= status <= 599:
                return status

        return None

    @staticmethod
    def _extract_content_length_from_text(
        value: str,
    ) -> int | None:
        """
        Extract a response length when a common length marker is present.
        """

        match = re.search(
            r"(?:length|size)\s*[:=]\s*(\d+)",
            value,
            re.IGNORECASE,
        )

        if match:
            return int(
                match.group(
                    1
                )
            )

        return None

    ###########################################################################
    # Normalization
    ###########################################################################

    @staticmethod
    def _normalize_url(
        value: Any,
    ) -> str | None:
        """
        Normalize an absolute HTTP(S) URL.
        """

        if not isinstance(
            value,
            str,
        ):
            return None

        value = value.strip()

        if not value:
            return None

        if not (
            value.startswith(
                "http://"
            )
            or value.startswith(
                "https://"
            )
        ):
            return None

        try:
            parsed = urlparse(
                value
            )

            if not parsed.scheme or not parsed.netloc:
                return None

        except ValueError:
            return None

        return value.rstrip(
            "/"
        ) or value

    @staticmethod
    def _normalize_route(
        value: Any,
    ) -> str | None:
        """
        Normalize an API route.
        """

        if not isinstance(
            value,
            str,
        ):
            return None

        route = value.strip()

        if not route:
            return None

        if route.startswith(
            "http://"
        ) or route.startswith(
            "https://"
        ):
            try:
                route = (
                    urlparse(
                        route
                    ).path
                    or "/"
                )

            except ValueError:
                return None

        if not route.startswith(
            "/"
        ):
            route = (
                f"/{route}"
            )

        return route

    @staticmethod
    def _normalize_method(
        value: Any,
    ) -> str | None:
        """
        Normalize an HTTP method.
        """

        if not isinstance(
            value,
            str,
        ):
            return None

        method = value.strip().upper()

        if method in {
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD",
            "TRACE",
        }:
            return method

        return None

    @staticmethod
    def _normalize_status_code(
        value: Any,
    ) -> int | None:
        """
        Normalize an HTTP status code.
        """

        if value is None:
            return None

        try:
            status = int(
                str(
                    value
                ).strip()
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        if 100 <= status <= 599:
            return status

        return None

    @staticmethod
    def _normalize_integer(
        value: Any,
    ) -> int | None:
        """
        Normalize an integer-valued field.
        """

        if value is None:
            return None

        try:
            number = int(
                str(
                    value
                ).strip()
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        if number < 0:
            return None

        return number

    ###########################################################################
    # URL / Target Helpers
    ###########################################################################

    @staticmethod
    def _join_target_route(
        target: str | None,
        route: str,
    ) -> str | None:
        """
        Construct an absolute endpoint URL from the assessment target and
        discovered API route when possible.
        """

        if not target:
            return None

        target = target.strip()

        if not (
            target.startswith(
                "http://"
            )
            or target.startswith(
                "https://"
            )
        ):
            return None

        return (
            target.rstrip(
                "/"
            )
            + "/"
            + route.lstrip(
                "/"
            )
        )

    @staticmethod
    def _extract_route(
        url: str,
    ) -> str:
        """
        Extract the path component from an absolute URL.
        """

        try:
            parsed = urlparse(
                url
            )

            path = (
                parsed.path
                or "/"
            )

            if parsed.query:
                return (
                    f"{path}?{parsed.query}"
                )

            return path

        except ValueError:
            return "/"

    @staticmethod
    def _extract_host(
        url: str | None,
    ) -> str | None:
        """
        Extract a hostname from an endpoint URL.
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
        Extract an explicit or effective port from an endpoint URL.
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


###############################################################################
# Public API
###############################################################################


__all__ = [
    "KiterunnerCollector",
]
