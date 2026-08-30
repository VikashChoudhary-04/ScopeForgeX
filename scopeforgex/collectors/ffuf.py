"""
ScopeForgeX FFUF Collector
==========================

Parses ffuf content and parameter discovery output into structured
ScopeForgeX observations.

FFUF is responsible for discovering hidden web content, files, directories,
virtual hosts and parameters.

Primary observations:

    HIDDEN_ENDPOINT
    DIRECTORY
    FILE
    PARAMETER
    VHOST

Architecture
------------

ffuf
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
FFUFCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes ffuf.
- The collector never constructs ffuf commands.
- Raw ffuf output remains preserved in the ExecutionResult artifacts.
- JSON and JSONL-style output are supported.
- Plain-text output is supported where a URL can be identified.
- Duplicate observations are removed deterministically.
- HTTP status and response metadata remain observation metadata.
- Discovery does not imply that a resource is vulnerable.
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


TOOL_NAME = "ffuf"

OBSERVATION_HIDDEN_ENDPOINT = "HIDDEN_ENDPOINT"
OBSERVATION_DIRECTORY = "DIRECTORY"
OBSERVATION_FILE = "FILE"
OBSERVATION_PARAMETER = "PARAMETER"
OBSERVATION_VHOST = "VHOST"


###############################################################################
# Collector
###############################################################################


class FFUFCollector(CollectorBase):
    """
    Collect structured discovery observations from ffuf output.

    FFUF can produce JSON output containing a ``results`` array as well as
    line-oriented output. The collector accepts both forms.

    The collector is deliberately discovery-focused. It records what ffuf
    found without deciding whether a discovered resource is vulnerable.
    """

    name = "ffuf"
    tool = "ffuf"

    description = (
        "Parses ffuf content and parameter discovery output into hidden "
        "endpoint, directory, file, parameter and virtual-host observations."
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
        Parse ffuf output into structured observations.

        The parser checks:

        1. ExecutionResult stdout
        2. ExecutionResult artifacts

        JSON result files are preferred for structured discovery metadata.
        Plain-text URL records are also accepted.
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
                str,
            ]
        ] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed = self._parse_record(
                    record
                )

                if parsed is None:
                    continue

                observation_type = (
                    parsed["observation_type"]
                )

                value = parsed["value"]

                url = self._normalize_url(
                    parsed.get(
                        "url"
                    )
                    or ""
                )

                host = (
                    self._extract_host(
                        url
                    )
                    if url
                    else self._extract_host(
                        parsed.get(
                            "host"
                        )
                        or ""
                    )
                )

                port = (
                    self._extract_port(
                        url
                    )
                    if url
                    else parsed.get(
                        "port"
                    )
                )

                key = (
                    observation_type,
                    value,
                    url or host or "",
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                metadata = dict(
                    parsed.get(
                        "metadata",
                        {},
                    )
                )

                metadata[
                    "source"
                ] = source

                observations.append(
                    CollectorObservation(
                        observation_type=observation_type,
                        value=value,
                        target=target,
                        host=host,
                        port=port,
                        url=url or None,
                        parameter=(
                            value
                            if observation_type
                            == OBSERVATION_PARAMETER
                            else None
                        ),
                        evidence=record,
                        source_tool=TOOL_NAME,
                        detection_method=(
                            self._detection_method(
                                observation_type
                            )
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
        Return available ffuf evidence as labelled text.

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
        Convert ffuf output into logical records.

        Supported formats:

        - JSON document containing ``results``
        - JSON document containing a single result
        - JSONL result objects
        - Plain-text discovery lines
        """

        content = content.strip()

        if not content:
            return []

        #######################################################################
        # Complete JSON document
        #######################################################################

        try:
            document = json.loads(
                content
            )

        except json.JSONDecodeError:
            document = None

        if isinstance(
            document,
            dict,
        ):
            results = document.get(
                "results"
            )

            if isinstance(
                results,
                list,
            ):
                return list(
                    results
                )

            if self._looks_like_result(
                document
            ):
                return [
                    document
                ]

        if isinstance(
            document,
            list,
        ):
            return list(
                document
            )

        #######################################################################
        # JSONL / Plain Text
        #######################################################################

        records: list[Any] = []

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

    @staticmethod
    def _looks_like_result(
        record: Mapping[str, Any],
    ) -> bool:
        """
        Determine whether a mapping resembles an ffuf result record.
        """

        return any(
            key in record
            for key in (
                "url",
                "input",
                "host",
                "status",
                "status_code",
                "length",
                "words",
            )
        )

    def _parse_record(
        self,
        record: Any,
    ) -> dict[str, Any] | None:
        """
        Normalize an ffuf record into the collector's internal format.
        """

        if isinstance(
            record,
            str,
        ):
            return self._parse_text_record(
                record
            )

        if not isinstance(
            record,
            Mapping,
        ):
            return None

        #######################################################################
        # Virtual host discovery
        #######################################################################

        host = self._extract_mapping_value(
            record,
            (
                "host",
                "hostname",
                "vhost",
            ),
        )

        url = self._extract_url(
            record
        )

        input_value = self._extract_mapping_value(
            record,
            (
                "input",
                "FUZZ",
                "input_value",
            ),
        )

        if (
            host
            and not url
            and self._looks_like_hostname(
                host
            )
        ):
            return {
                "observation_type": OBSERVATION_VHOST,
                "value": host,
                "host": host,
                "url": None,
                "metadata": self._result_metadata(
                    record
                ),
            }

        #######################################################################
        # Parameter discovery
        #######################################################################

        parameter = self._extract_parameter(
            record
        )

        if parameter:
            parameter_url = (
                url
                or self._extract_base_url(
                    record
                )
            )

            return {
                "observation_type": (
                    OBSERVATION_PARAMETER
                ),
                "value": parameter,
                "url": parameter_url,
                "host": (
                    self._extract_host(
                        parameter_url
                    )
                    if parameter_url
                    else host
                ),
                "port": (
                    self._extract_port(
                        parameter_url
                    )
                    if parameter_url
                    else None
                ),
                "metadata": self._result_metadata(
                    record
                ),
            }

        #######################################################################
        # URL/content discovery
        #######################################################################

        if not url:
            return None

        normalized_url = self._normalize_url(
            url
        )

        if not normalized_url:
            return None

        observation_type = (
            self._classify_discovery(
                normalized_url
            )
        )

        return {
            "observation_type": observation_type,
            "value": normalized_url,
            "url": normalized_url,
            "host": self._extract_host(
                normalized_url
            ),
            "port": self._extract_port(
                normalized_url
            ),
            "metadata": self._result_metadata(
                record
            ),
        }

    def _parse_text_record(
        self,
        record: str,
    ) -> dict[str, Any] | None:
        """
        Parse a plain-text ffuf discovery record.

        The safest text representation to collect is an HTTP(S) URL. Lines
        that cannot be confidently interpreted as URLs are ignored rather
        than converted into potentially incorrect findings.
        """

        value = record.strip()

        if not self._looks_like_url(
            value
        ):
            return None

        url = self._normalize_url(
            value
        )

        if not url:
            return None

        observation_type = (
            self._classify_discovery(
                url
            )
        )

        return {
            "observation_type": observation_type,
            "value": url,
            "url": url,
            "host": self._extract_host(
                url
            ),
            "port": self._extract_port(
                url
            ),
            "metadata": {},
        }

    ###########################################################################
    # FFUF Result Extraction
    ###########################################################################

    @staticmethod
    def _extract_mapping_value(
        record: Mapping[str, Any],
        keys: tuple[str, ...],
    ) -> str | None:
        """
        Return the first non-empty textual value from a mapping.
        """

        for key in keys:

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

    @classmethod
    def _extract_url(
        cls,
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract the discovered URL from an ffuf result.
        """

        candidates = (
            "url",
            "redirectlocation",
            "redirect_location",
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

                if cls._looks_like_url(
                    value
                ):
                    return value

        input_value = record.get(
            "input"
        )

        if isinstance(
            input_value,
            Mapping,
        ):
            for value in input_value.values():

                if isinstance(
                    value,
                    str,
                ) and cls._looks_like_url(
                    value.strip()
                ):
                    return value.strip()

        return None

    @staticmethod
    def _extract_parameter(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a parameter name from an ffuf result.

        Parameter discovery output may represent the fuzzed value through an
        input mapping. The collector prefers an explicit parameter field and
        otherwise recognizes common parameter-oriented fields.
        """

        explicit_keys = (
            "parameter",
            "param",
            "parameter_name",
            "param_name",
        )

        for key in explicit_keys:

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

        input_value = record.get(
            "input"
        )

        if isinstance(
            input_value,
            Mapping,
        ):
            for key, value in input_value.items():

                key = str(
                    key
                ).strip()

                if (
                    key
                    and key.lower()
                    not in {
                        "url",
                        "host",
                    }
                ):
                    return key

        return None

    @staticmethod
    def _extract_base_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a base URL associated with a parameter result.
        """

        for key in (
            "url",
            "target",
            "base_url",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                value = value.strip()

                if (
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
    def _result_metadata(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve useful ffuf result metadata without replacing raw evidence.
        """

        metadata: dict[str, Any] = {}

        fields = (
            "status",
            "status_code",
            "length",
            "words",
            "lines",
            "content-type",
            "content_type",
            "redirectlocation",
            "host",
            "input",
        )

        for field in fields:

            if field in record:
                metadata[field] = record.get(
                    field
                )

        return metadata

    ###########################################################################
    # Discovery Classification
    ###########################################################################

    @classmethod
    def _classify_discovery(
        cls,
        url: str,
    ) -> str:
        """
        Classify a discovered URL as a file, directory or generic endpoint.
        """

        parsed = urlparse(
            url
        )

        path = (
            parsed.path
            or "/"
        ).lower()

        if path.endswith(
            "/"
        ):
            return OBSERVATION_DIRECTORY

        file_extensions = {
            ".7z",
            ".bak",
            ".backup",
            ".bz2",
            ".cfg",
            ".conf",
            ".config",
            ".csv",
            ".db",
            ".gz",
            ".htm",
            ".html",
            ".ini",
            ".jar",
            ".json",
            ".js",
            ".log",
            ".old",
            ".pdf",
            ".php",
            ".rar",
            ".sql",
            ".tar",
            ".tgz",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
            ".zip",
        }

        for extension in file_extensions:

            if path.endswith(
                extension
            ):
                return OBSERVATION_FILE

        return OBSERVATION_HIDDEN_ENDPOINT

    @staticmethod
    def _detection_method(
        observation_type: str,
    ) -> str:
        """
        Return the detection method associated with an observation type.
        """

        methods = {
            OBSERVATION_HIDDEN_ENDPOINT: (
                "ffuf content discovery"
            ),
            OBSERVATION_DIRECTORY: (
                "ffuf directory discovery"
            ),
            OBSERVATION_FILE: (
                "ffuf file discovery"
            ),
            OBSERVATION_PARAMETER: (
                "ffuf parameter discovery"
            ),
            OBSERVATION_VHOST: (
                "ffuf virtual host discovery"
            ),
        }

        return methods.get(
            observation_type,
            "ffuf discovery",
        )

    ###########################################################################
    # URL Helpers
    ###########################################################################

    @staticmethod
    def _looks_like_url(
        value: str,
    ) -> bool:
        """
        Return whether a value appears to be an HTTP(S) URL.
        """

        value = str(
            value
        ).strip()

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
        Normalize a discovered HTTP URL while preserving path/query data.
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
    def _extract_host(
        url: str,
    ) -> str | None:
        """
        Extract a hostname from a URL or hostname-like value.
        """

        if not url:
            return None

        try:
            parsed = urlparse(
                url
            )

            if parsed.hostname:
                return parsed.hostname

        except ValueError:
            return None

        return None

    @staticmethod
    def _extract_port(
        url: str,
    ) -> int | None:
        """
        Extract an explicit or effective HTTP port.
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
    def _looks_like_hostname(
        value: str,
    ) -> bool:
        """
        Determine whether a value appears to be a hostname.
        """

        value = str(
            value
        ).strip()

        if not value:
            return False

        if (
            "://" in value
            or "/" in value
            or " " in value
        ):
            return False

        return True

    ###########################################################################
    # Target Resolution
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


###############################################################################
# Public API
###############################################################################


__all__ = [
    "FFUFCollector",
]
