"""
ScopeForgeX SQLMap Collector
============================

Parses SQLMap output into structured ScopeForgeX observations.

SQLMap is responsible for specialized SQL injection detection and validation.

Primary observations:

    SQL_INJECTION
    SQL_INJECTION_PARAMETER
    SQL_INJECTION_TECHNIQUE
    DATABASE_FINGERPRINT
    DATABASE_INFORMATION

Architecture
------------

SQLMap
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
SQLMapCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes SQLMap.
- The collector never constructs SQLMap commands.
- Raw SQLMap output remains preserved in the ExecutionResult artifacts.
- Plain-text SQLMap output is supported.
- JSON and JSONL-style records are supported when available.
- SQL injection findings retain the affected parameter and URL when present.
- Database fingerprint information is represented as structured observations.
- Detection evidence is preserved without automatically implying confirmation.
- The collector does not assign final severity or risk.
- Duplicate observations are removed deterministically.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlparse

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "sqlmap"

OBSERVATION_SQL_INJECTION = "SQL_INJECTION"
OBSERVATION_SQL_INJECTION_PARAMETER = "SQL_INJECTION_PARAMETER"
OBSERVATION_SQL_INJECTION_TECHNIQUE = "SQL_INJECTION_TECHNIQUE"
OBSERVATION_DATABASE_FINGERPRINT = "DATABASE_FINGERPRINT"
OBSERVATION_DATABASE_INFORMATION = "DATABASE_INFORMATION"


###############################################################################
# Collector
###############################################################################


class SQLMapCollector(CollectorBase):
    """
    Collect structured SQL injection observations from SQLMap output.

    SQLMap is treated as a specialized validation tool. The collector turns
    its output into normalized observations while preserving the original
    execution evidence.

    The collector does not independently exploit, validate or reproduce a
    suspected SQL injection.
    """

    name = "sqlmap"
    tool = "sqlmap"

    description = (
        "Parses SQLMap output into SQL injection, affected parameter, "
        "technique and database observations."
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
        Parse SQLMap output into structured observations.
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
            tuple[str, str, str | None, str | None]
        ] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed_records = self._parse_record(
                    record
                )

                for parsed in parsed_records:

                    observation_type = parsed.get(
                        "observation_type"
                    )

                    value = parsed.get(
                        "value"
                    )

                    if not observation_type:
                        continue

                    if value is None:
                        continue

                    value = str(
                        value
                    ).strip()

                    if not value:
                        continue

                    host = parsed.get(
                        "host"
                    )

                    parameter = parsed.get(
                        "parameter"
                    )

                    key = (
                        observation_type,
                        value.lower(),
                        host,
                        parameter,
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
                        self._build_observation(
                            observation_type=(
                                observation_type
                            ),
                            value=value,
                            target=target,
                            host=host,
                            port=parsed.get(
                                "port"
                            ),
                            url=parsed.get(
                                "url"
                            ),
                            parameter=parameter,
                            evidence=parsed.get(
                                "evidence",
                                record,
                            ),
                            metadata=metadata,
                            confidence=parsed.get(
                                "confidence",
                                "informational",
                            ),
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
        Return available SQLMap evidence as labelled text.

        Persistent artifacts are processed before stdout.
        """

        contents: list[tuple[str, str]] = []

        artifacts = self.get_artifacts(
            execution_result
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
    # Record Handling
    ###########################################################################

    def _iter_records(
        self,
        content: str,
    ) -> list[Any]:
        """
        Convert SQLMap output into logical records.

        SQLMap normally produces human-readable multiline output. Structured
        JSON and JSONL records are also accepted when supplied by an adapter
        or execution artifact.
        """

        content = content.strip()

        if not content:
            return []

        document = self._parse_json_document(
            content
        )

        if document is not None:

            if isinstance(
                document,
                Mapping,
            ):
                return [
                    document
                ]

            if isinstance(
                document,
                list,
            ):
                return [
                    item
                    for item in document
                    if isinstance(
                        item,
                        (Mapping, str),
                    )
                ]

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
                    Mapping,
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
    def _parse_json_document(
        content: str,
    ) -> Any | None:
        """
        Attempt to parse a complete JSON document.
        """

        try:
            return json.loads(
                content
            )

        except json.JSONDecodeError:
            return None

    ###########################################################################
    # Record Parsing
    ###########################################################################

    def _parse_record(
        self,
        record: Any,
    ) -> list[dict[str, Any]]:
        """
        Parse a single SQLMap record.
        """

        if isinstance(
            record,
            Mapping,
        ):
            return self._parse_mapping_record(
                record
            )

        if isinstance(
            record,
            str,
        ):
            return self._parse_text_record(
                record
            )

        return []

    def _parse_mapping_record(
        self,
        record: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Parse a structured SQLMap record.
        """

        observations: list[dict[str, Any]] = []

        url = self._extract_url(
            record
        )

        host = self._extract_host(
            record,
            url,
        )

        port = self._extract_port(
            record,
            url,
        )

        parameter = self._extract_parameter(
            record
        )

        evidence = dict(
            record
        )

        text = self._combined_text(
            record,
            (
                "title",
                "finding",
                "message",
                "description",
                "type",
                "technique",
                "dbms",
                "database",
            ),
        )

        if self._mapping_indicates_sql_injection(
            record,
            text,
        ):

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SQL_INJECTION
                    ),
                    "value": (
                        self._mapping_value(
                            record,
                            (
                                "finding",
                                "title",
                                "message",
                                "description",
                            ),
                        )
                        or "SQL injection detected"
                    ),
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": evidence,
                    "metadata": {},
                    "confidence": (
                        self._mapping_confidence(
                            record
                        )
                    ),
                }
            )

        if parameter:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SQL_INJECTION_PARAMETER
                    ),
                    "value": parameter,
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": evidence,
                    "metadata": {},
                }
            )

        technique = self._mapping_value(
            record,
            (
                "technique",
                "injection_type",
                "sql_injection_type",
                "type",
            ),
        )

        if technique and self._looks_like_sql_technique(
            str(
                technique
            )
        ):

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SQL_INJECTION_TECHNIQUE
                    ),
                    "value": str(
                        technique
                    ).strip(),
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": evidence,
                    "metadata": {},
                }
            )

        dbms = self._mapping_value(
            record,
            (
                "dbms",
                "database",
                "database_type",
                "backend",
            ),
        )

        if dbms:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_DATABASE_FINGERPRINT
                    ),
                    "value": str(
                        dbms
                    ).strip(),
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": evidence,
                    "metadata": {},
                }
            )

        database_name = self._mapping_value(
            record,
            (
                "database_name",
                "schema",
                "current_db",
                "current_database",
            ),
        )

        if database_name:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_DATABASE_INFORMATION
                    ),
                    "value": str(
                        database_name
                    ).strip(),
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": evidence,
                    "metadata": {},
                }
            )

        return observations

    def _parse_text_record(
        self,
        line: str,
    ) -> list[dict[str, Any]]:
        """
        Parse a single SQLMap text line.

        SQLMap's most useful findings are normally expressed across multiple
        lines. This parser therefore extracts only information that can be
        safely associated with the current line.
        """

        text = line.strip()

        if not text:
            return []

        url = self._extract_url_from_text(
            text
        )

        host = None
        port = None

        if url:
            host = self._host_from_url(
                url
            )
            port = self._port_from_url(
                url
            )

        parameter = self._extract_parameter_from_text(
            text
        )

        observations: list[dict[str, Any]] = []

        if self._text_indicates_sql_injection(
            text
        ):

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SQL_INJECTION
                    ),
                    "value": self._extract_sql_finding_value(
                        text
                    ),
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": text,
                    "metadata": {
                        "raw_line": text,
                    },
                    "confidence": "informational",
                }
            )

        technique = self._extract_technique_from_text(
            text
        )

        if technique:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_SQL_INJECTION_TECHNIQUE
                    ),
                    "value": technique,
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": text,
                    "metadata": {
                        "raw_line": text,
                    },
                }
            )

        dbms = self._extract_dbms_from_text(
            text
        )

        if dbms:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_DATABASE_FINGERPRINT
                    ),
                    "value": dbms,
                    "host": host,
                    "port": port,
                    "url": url,
                    "parameter": parameter,
                    "evidence": text,
                    "metadata": {
                        "raw_line": text,
                    },
                }
            )

        return observations

    ###########################################################################
    # SQL Injection Detection
    ###########################################################################

    @staticmethod
    def _mapping_indicates_sql_injection(
        record: Mapping[str, Any],
        text: str,
    ) -> bool:
        """
        Determine whether structured evidence explicitly represents SQL
        injection.
        """

        for key in (
            "vulnerable",
            "injectable",
            "sql_injection",
            "is_vulnerable",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                bool,
            ) and value:
                return True

            if isinstance(
                value,
                str,
            ) and value.strip().lower() in {
                "true",
                "yes",
                "vulnerable",
                "injectable",
            }:
                return True

        return SQLMapCollector._text_indicates_sql_injection(
            text
        )

    @staticmethod
    def _text_indicates_sql_injection(
        text: str,
    ) -> bool:
        """
        Return whether a text line contains strong SQLMap SQL-injection
        indicators.
        """

        normalized = text.lower()

        indicators = (
            "is vulnerable",
            "is injectable",
            "parameter is vulnerable",
            "parameter is injectable",
            "sql injection",
            "injectable parameter",
            "payload:",
            "type:",
            "title:",
        )

        if (
            "parameter" in normalized
            and (
                "vulnerable" in normalized
                or "injectable" in normalized
            )
        ):
            return True

        return any(
            indicator in normalized
            for indicator in indicators[:5]
        )

    ###########################################################################
    # Parameter Extraction
    ###########################################################################

    @staticmethod
    def _extract_parameter(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an affected parameter from structured SQLMap evidence.
        """

        for key in (
            "parameter",
            "param",
            "parameter_name",
            "injectable_parameter",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip()

        return None

    @staticmethod
    def _extract_parameter_from_text(
        text: str,
    ) -> str | None:
        """
        Extract an affected parameter from a SQLMap text line.
        """

        patterns = (
            r"parameter\s+['\"]?([^'\"\s:]+)",
            r"param(?:eter)?\s*[:=]\s*['\"]?([^'\"\s]+)",
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            )

            if match:
                return match.group(
                    1
                ).strip()

        return None

    ###########################################################################
    # Technique Extraction
    ###########################################################################

    @staticmethod
    def _looks_like_sql_technique(
        value: str,
    ) -> bool:
        """
        Determine whether a value resembles a SQLMap injection technique.
        """

        normalized = value.lower()

        indicators = (
            "boolean",
            "error-based",
            "time-based",
            "union",
            "stacked",
            "inline",
            "out-of-band",
            "oob",
            "blind",
        )

        return any(
            indicator in normalized
            for indicator in indicators
        )

    @classmethod
    def _extract_technique_from_text(
        cls,
        text: str,
    ) -> str | None:
        """
        Extract an SQL injection technique from a SQLMap text line.
        """

        if not cls._looks_like_sql_technique(
            text
        ):
            return None

        match = re.search(
            r"(boolean-based|error-based|time-based|union(?: query)?|stacked queries?|inline query|out-of-band|blind)",
            text,
            flags=re.IGNORECASE,
        )

        if match:
            return match.group(
                1
            ).strip()

        return None

    ###########################################################################
    # Database Extraction
    ###########################################################################

    @staticmethod
    def _extract_dbms_from_text(
        text: str,
    ) -> str | None:
        """
        Extract a database management system fingerprint from SQLMap output.
        """

        patterns = (
            r"back-end DBMS\s*:\s*(.+)$",
            r"back-end DBMS\s+is\s+(.+)$",
            r"database management system\s*:\s*(.+)$",
            r"DBMS\s*:\s*(.+)$",
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            )

            if match:
                value = match.group(
                    1
                ).strip()

                if value:
                    return value

        return None

    ###########################################################################
    # URL Extraction
    ###########################################################################

    @staticmethod
    def _extract_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract an HTTP(S) URL from structured SQLMap evidence.
        """

        for key in (
            "url",
            "target",
            "endpoint",
            "request_url",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):

                candidate = value.strip()

                if candidate.startswith(
                    (
                        "http://",
                        "https://",
                    )
                ):
                    return candidate

        return None

    @staticmethod
    def _extract_url_from_text(
        text: str,
    ) -> str | None:
        """
        Extract the first HTTP(S) URL from text.
        """

        match = re.search(
            r"https?://[^\s'\"<>]+",
            text,
            flags=re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(
            0
        ).rstrip(
            ".,;)"
        )

    ###########################################################################
    # Host / Port Helpers
    ###########################################################################

    @staticmethod
    def _extract_host(
        record: Mapping[str, Any],
        url: str | None,
    ) -> str | None:
        """
        Extract the affected host.
        """

        for key in (
            "host",
            "hostname",
            "fqdn",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                return value.strip().lower()

        if url:
            return SQLMapCollector._host_from_url(
                url
            )

        return None

    @staticmethod
    def _extract_port(
        record: Mapping[str, Any],
        url: str | None,
    ) -> int | None:
        """
        Extract the affected port.
        """

        value = record.get(
            "port"
        )

        if value is not None:

            try:
                return int(
                    value
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        if url:
            return SQLMapCollector._port_from_url(
                url
            )

        return None

    @staticmethod
    def _host_from_url(
        url: str,
    ) -> str | None:
        """
        Extract hostname from an HTTP(S) URL.
        """

        try:
            return urlparse(
                url
            ).hostname

        except ValueError:
            return None

    @staticmethod
    def _port_from_url(
        url: str,
    ) -> int | None:
        """
        Extract explicit or effective HTTP(S) port.
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

    ###########################################################################
    # Mapping Helpers
    ###########################################################################

    @staticmethod
    def _mapping_value(
        record: Mapping[str, Any],
        keys: Iterable[str],
    ) -> Any:
        """
        Return the first meaningful scalar mapping value.
        """

        for key in keys:

            value = record.get(
                key
            )

            if value in (
                None,
                "",
                [],
                {},
            ):
                continue

            if isinstance(
                value,
                (str, int, float, bool),
            ):
                return value

        return None

    @staticmethod
    def _combined_text(
        record: Mapping[str, Any],
        keys: Iterable[str],
    ) -> str:
        """
        Combine scalar fields into searchable text.
        """

        values: list[str] = []

        for key in keys:

            value = record.get(
                key
            )

            if value in (
                None,
                "",
            ):
                continue

            if isinstance(
                value,
                (str, int, float, bool),
            ):
                values.append(
                    str(
                        value
                    )
                )

        return " ".join(
            values
        )

    @staticmethod
    def _mapping_confidence(
        record: Mapping[str, Any],
    ) -> str:
        """
        Preserve an explicit normalized confidence when supplied.
        """

        value = record.get(
            "confidence"
        )

        if value is None:
            return "informational"

        normalized = str(
            value
        ).strip().lower()

        if normalized in {
            "confirmed",
            "high",
            "medium",
            "low",
            "informational",
        }:
            return normalized

        return "informational"

    ###########################################################################
    # Finding Value Helpers
    ###########################################################################

    @staticmethod
    def _extract_sql_finding_value(
        text: str,
    ) -> str:
        """
        Produce a concise SQL injection observation value.
        """

        parameter = (
            SQLMapCollector
            ._extract_parameter_from_text(
                text
            )
        )

        if parameter:
            return (
                f"SQL injection candidate: "
                f"{parameter}"
            )

        return "SQL injection detected"

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

    ###########################################################################
    # Observation Construction
    ###########################################################################

    @staticmethod
    def _build_observation(
        *,
        observation_type: str,
        value: str,
        target: str | None,
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        parameter: str | None = None,
        evidence: Any = None,
        metadata: Mapping[str, Any] | None = None,
        confidence: str = "informational",
    ) -> CollectorObservation:
        """
        Build a canonical CollectorObservation.
        """

        detection_methods = {
            OBSERVATION_SQL_INJECTION: (
                "SQLMap SQL injection assessment"
            ),
            OBSERVATION_SQL_INJECTION_PARAMETER: (
                "SQLMap injectable parameter identification"
            ),
            OBSERVATION_SQL_INJECTION_TECHNIQUE: (
                "SQLMap injection technique identification"
            ),
            OBSERVATION_DATABASE_FINGERPRINT: (
                "SQLMap database fingerprinting"
            ),
            OBSERVATION_DATABASE_INFORMATION: (
                "SQLMap database information discovery"
            ),
        }

        return CollectorObservation(
            observation_type=observation_type,
            value=value,
            target=target,
            host=host,
            port=port,
            url=url,
            parameter=parameter,
            evidence=evidence,
            source_tool=TOOL_NAME,
            detection_method=detection_methods.get(
                observation_type,
                "SQLMap SQL injection assessment",
            ),
            confidence=confidence,
            metadata=dict(
                metadata or {}
            ),
        )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SQLMapCollector",
]
