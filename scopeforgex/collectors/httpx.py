"""
ScopeForgeX HTTPX Collector
===========================

Parses httpx probing output into structured ScopeForgeX observations.

httpx is responsible for determining which discovered hosts expose HTTP
services and for collecting basic HTTP service metadata.

Primary observations:

    HTTP_SERVICE
    HTTP_STATUS
    WEB_SERVER

Additional metadata may include:

    URL
    HOST
    PORT
    TITLE
    TECHNOLOGY
    CONTENT_TYPE
    METHOD
    RESPONSE_TIME
    CONTENT_LENGTH

Architecture
------------

httpx
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
HTTPXCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes httpx.
- The collector never constructs httpx commands.
- Raw httpx output remains preserved in the ExecutionResult artifacts.
- JSONL output is preferred when available.
- Plain-text URL output is supported.
- Duplicate services are removed deterministically.
- The collector does not assign final severity or risk.
- HTTP service discovery is an observation, not a vulnerability.
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


TOOL_NAME = "httpx"

OBSERVATION_HTTP_SERVICE = "HTTP_SERVICE"
OBSERVATION_HTTP_STATUS = "HTTP_STATUS"
OBSERVATION_WEB_SERVER = "WEB_SERVER"


###############################################################################
# Collector
###############################################################################


class HTTPXCollector(CollectorBase):
    """
    Collect structured HTTP service observations from httpx output.

    httpx may emit either plain URLs or JSONL records containing additional
    probe metadata. The collector supports both representations.
    """

    name = "httpx"
    tool = "httpx"

    description = (
        "Parses httpx HTTP probing output into HTTP service, HTTP status "
        "and web server observations."
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
        Parse httpx output into structured observations.

        The parser checks:

        1. ExecutionResult stdout
        2. ExecutionResult artifacts

        Artifact content is retained as evidence when available.
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

        seen_services: set[str] = set()
        seen_statuses: set[tuple[str, str]] = set()
        seen_servers: set[tuple[str, str]] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed = self._parse_record(
                    record
                )

                if parsed is None:
                    continue

                url = self._normalize_url(
                    parsed.get(
                        "url",
                        "",
                    )
                )

                if not url:
                    continue

                host = self._extract_host(
                    url
                )

                port = self._extract_port(
                    url
                )

                metadata = parsed.get(
                    "metadata",
                    {},
                )

                if not isinstance(
                    metadata,
                    Mapping,
                ):
                    metadata = {}

                evidence = record

                ################################################################
                # HTTP Service
                ################################################################

                if url not in seen_services:
                    seen_services.add(
                        url
                    )

                    observations.append(
                        CollectorObservation(
                            observation_type=(
                                OBSERVATION_HTTP_SERVICE
                            ),
                            value=url,
                            target=target,
                            host=host,
                            port=port,
                            url=url,
                            evidence=evidence,
                            source_tool=TOOL_NAME,
                            detection_method=(
                                "httpx HTTP service probing"
                            ),
                            confidence="informational",
                            metadata={
                                "source": source,
                                **dict(
                                    metadata
                                ),
                            },
                        )
                    )

                ################################################################
                # HTTP Status
                ################################################################

                status = self._extract_status(
                    parsed
                )

                if status is not None:
                    status_key = (
                        url,
                        str(status),
                    )

                    if status_key not in seen_statuses:
                        seen_statuses.add(
                            status_key
                        )

                        observations.append(
                            CollectorObservation(
                                observation_type=(
                                    OBSERVATION_HTTP_STATUS
                                ),
                                value=str(
                                    status
                                ),
                                target=target,
                                host=host,
                                port=port,
                                url=url,
                                evidence=evidence,
                                source_tool=TOOL_NAME,
                                detection_method=(
                                    "httpx HTTP status probing"
                                ),
                                confidence="informational",
                                metadata={
                                    "source": source,
                                    "status_code": status,
                                },
                            )
                        )

                ################################################################
                # Web Server
                ################################################################

                server = self._extract_server(
                    parsed
                )

                if server:
                    server_key = (
                        url,
                        server,
                    )

                    if server_key not in seen_servers:
                        seen_servers.add(
                            server_key
                        )

                        observations.append(
                            CollectorObservation(
                                observation_type=(
                                    OBSERVATION_WEB_SERVER
                                ),
                                value=server,
                                target=target,
                                host=host,
                                port=port,
                                url=url,
                                evidence=evidence,
                                source_tool=TOOL_NAME,
                                detection_method=(
                                    "httpx web server detection"
                                ),
                                confidence="informational",
                                metadata={
                                    "source": source,
                                    "server": server,
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
        Return available httpx evidence as labelled text.

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

    @staticmethod
    def _iter_records(
        content: str,
    ) -> list[str | dict[str, Any]]:
        """
        Convert raw httpx content into logical records.

        JSON objects are retained as dictionaries so their probe metadata can
        be extracted. Non-JSON lines are retained as plain-text records.
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
        Normalize a raw httpx record into an internal representation.
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
                "metadata": {},
            }

        url = self._extract_url_from_mapping(
            record
        )

        if not url:
            return None

        return {
            "url": url,
            "metadata": dict(
                record
            ),
        }

    @staticmethod
    def _extract_url_from_mapping(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract the HTTP URL from a structured httpx record.

        httpx JSON output commonly uses "url", while alternate output
        representations may expose the value through "input" or "host".
        """

        candidates = (
            "url",
            "input",
            "request",
        )

        for key in candidates:

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):
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

        host = record.get(
            "host"
        )

        if isinstance(
            host,
            str,
        ):
            host = host.strip()

            if host.startswith(
                "http://"
            ) or host.startswith(
                "https://"
            ):
                return host

        return None

    ###########################################################################
    # Metadata Extraction
    ###########################################################################

    @staticmethod
    def _extract_status(
        parsed: Mapping[str, Any],
    ) -> int | None:
        """
        Extract an HTTP status code from a parsed record.
        """

        metadata = parsed.get(
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            return None

        candidates = (
            "status_code",
            "status-code",
            "status",
        )

        for key in candidates:

            value = metadata.get(
                key
            )

            try:
                if value is not None:
                    status = int(
                        value
                    )

                    if 100 <= status <= 599:
                        return status

            except (
                TypeError,
                ValueError,
            ):
                continue

        return None

    @staticmethod
    def _extract_server(
        parsed: Mapping[str, Any],
    ) -> str | None:
        """
        Extract the detected web server from a parsed record.
        """

        metadata = parsed.get(
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            return None

        candidates = (
            "webserver",
            "web-server",
            "server",
        )

        for key in candidates:

            value = metadata.get(
                key
            )

            if isinstance(
                value,
                str,
            ):
                normalized = value.strip()

                if normalized:
                    return normalized

        return None

    ###########################################################################
    # URL Normalization
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
        Normalize an HTTP URL while preserving meaningful path/query data.
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
        Extract the hostname from an HTTP URL.
        """

        try:
            return urlparse(
                url
            ).hostname

        except ValueError:
            return None

    @staticmethod
    def _extract_port(
        url: str,
    ) -> int | None:
        """
        Extract an explicit or effective HTTP port.
        """

        try:
            parsed = urlparse(
                url
            )

            if parsed.port is not None:
                return parsed.port

            scheme = parsed.scheme.lower()

            if scheme == "http":
                return 80

            if scheme == "https":
                return 443

        except ValueError:
            return None

        return None


###############################################################################
# Public API
###############################################################################


__all__ = [
    "HTTPXCollector",
]
