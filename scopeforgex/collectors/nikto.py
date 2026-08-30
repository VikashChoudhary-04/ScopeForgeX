"""
ScopeForgeX Nikto Collector
============================

Parses Nikto web-server assessment output into structured ScopeForgeX
observations.

Nikto is responsible for web-server-specific security assessment, including
common dangerous files, insecure configurations, outdated server components
and other web-server issues.

Primary observations:

    WEB_SERVER_ISSUE
    MISCONFIGURATION
    EXPOSED_FILE
    SERVER_VULNERABILITY

Architecture
------------

Nikto
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
NiktoCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes Nikto.
- The collector never constructs Nikto commands.
- Raw Nikto output remains preserved in the ExecutionResult artifacts.
- Structured XML output is supported when available.
- JSON-style records are supported when present.
- Standard line-oriented Nikto output is supported.
- Duplicate findings are removed deterministically.
- The collector preserves Nikto identifiers and OSVDB/CVE references when
  available.
- The collector does not assign final risk beyond preserving the available
  detection severity/confidence information.
- Collection failures do not destroy the original execution result.
- The collector never performs network requests.

v1.0.0
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "nikto"

OBSERVATION_WEB_SERVER_ISSUE = "WEB_SERVER_ISSUE"
OBSERVATION_MISCONFIGURATION = "MISCONFIGURATION"
OBSERVATION_EXPOSED_FILE = "EXPOSED_FILE"
OBSERVATION_SERVER_VULNERABILITY = "SERVER_VULNERABILITY"


###############################################################################
# Patterns
###############################################################################


_CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)

_OSVDB_PATTERN = re.compile(
    r"\bOSVDB[-:# ]?\d+\b",
    re.IGNORECASE,
)

_NIKTO_ID_PATTERN = re.compile(
    r"\b(?:OSVDB|CVE|NIKTO)[-:# ]?\d[\w.-]*\b",
    re.IGNORECASE,
)

_HTTP_URL_PATTERN = re.compile(
    r"https?://[^\s<>\[\]]+",
    re.IGNORECASE,
)

_HTTP_STATUS_PATTERN = re.compile(
    r"\b(?:HTTP/\d(?:\.\d)?\s+)?([1-5]\d{2})\b",
    re.IGNORECASE,
)

_SEVERITY_PATTERN = re.compile(
    r"\b(critical|high|medium|moderate|low|info|informational)\b",
    re.IGNORECASE,
)


###############################################################################
# Severity / Confidence Helpers
###############################################################################


_SEVERITY_ALIASES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "informational",
    "information": "informational",
    "informational": "informational",
}

_CONFIDENCE_BY_SEVERITY = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


###############################################################################
# Collector
###############################################################################


class NiktoCollector(CollectorBase):
    """
    Collect structured web-server observations from Nikto output.

    Nikto can emit plain text, XML and other structured formats depending on
    the selected execution options. The collector accepts the common forms
    without requiring the workflow to know which output format was selected.
    """

    name = "nikto"
    tool = "nikto"

    description = (
        "Parses Nikto web-server assessment output into structured "
        "ScopeForgeX observations."
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
        Parse Nikto output into structured observations.

        The collector checks stdout and execution artifacts. Structured XML
        artifacts are parsed when possible; otherwise content falls back to
        JSONL/plain-text parsing.
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

        seen: set[tuple[str, str, str, str]] = set()

        for source, content in contents:

            records = self._parse_content(
                content
            )

            for record in records:

                normalized = self._normalize_record(
                    record
                )

                if normalized is None:
                    continue

                key = (
                    str(
                        normalized.get(
                            "observation_type",
                            "",
                        )
                    ),
                    str(
                        normalized.get(
                            "title",
                            "",
                        )
                    ).lower(),
                    str(
                        normalized.get(
                            "url",
                            "",
                        )
                    ),
                    str(
                        normalized.get(
                            "identifier",
                            "",
                        )
                    ),
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                observations.append(
                    self._build_observation(
                        normalized,
                        target=target,
                        source=source,
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
        Return available Nikto evidence as labelled text.

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
    # Content Parsing
    ###########################################################################

    def _parse_content(
        self,
        content: str,
    ) -> list[dict[str, Any]]:
        """
        Detect and parse the available Nikto output format.
        """

        stripped = content.lstrip()

        if stripped.startswith(
            "<"
        ):
            xml_records = self._parse_xml(
                content
            )

            if xml_records:
                return xml_records

        json_records = self._parse_json(
            content
        )

        if json_records:
            return json_records

        return self._parse_plain_text(
            content
        )

    def _parse_json(
        self,
        content: str,
    ) -> list[dict[str, Any]]:
        """
        Parse JSON or JSONL Nikto-style records.
        """

        records: list[dict[str, Any]] = []

        stripped = content.strip()

        if not stripped:
            return records

        try:
            value = json.loads(
                stripped
            )

            if isinstance(
                value,
                Mapping,
            ):
                records.append(
                    dict(
                        value
                    )
                )

            elif isinstance(
                value,
                list,
            ):
                for item in value:
                    if isinstance(
                        item,
                        Mapping,
                    ):
                        records.append(
                            dict(
                                item
                            )
                        )

            if records:
                return records

        except json.JSONDecodeError:
            pass

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if not (
                line.startswith(
                    "{"
                )
                and line.endswith(
                    "}"
                )
            ):
                continue

            try:
                value = json.loads(
                    line
                )

            except json.JSONDecodeError:
                continue

            if isinstance(
                value,
                Mapping,
            ):
                records.append(
                    dict(
                        value
                    )
                )

        return records

    def _parse_xml(
        self,
        content: str,
    ) -> list[dict[str, Any]]:
        """
        Parse common Nikto XML result structures.

        The parser intentionally accepts several possible element names because
        Nikto XML output can differ depending on version and output options.
        """

        records: list[dict[str, Any]] = []

        try:
            root = ET.fromstring(
                content
            )

        except ET.ParseError:
            return records

        default_url = self._xml_find_text(
            root,
            (
                "uri",
                "url",
                "host",
            ),
        )

        for element in root.iter():

            tag = self._local_name(
                element.tag
            ).lower()

            if tag not in {
                "item",
                "finding",
                "vulnerability",
                "result",
                "issue",
            }:
                continue

            record: dict[str, Any] = {}

            for key, value in element.attrib.items():
                record[
                    self._local_name(
                        key
                    )
                ] = value

            for child in element:
                child_name = self._local_name(
                    child.tag
                )

                text = (
                    child.text.strip()
                    if child.text
                    else ""
                )

                if text:
                    record[
                        child_name
                    ] = text

            if default_url and not self._record_url(
                record
            ):
                record[
                    "url"
                ] = default_url

            if record:
                records.append(
                    record
                )

        return records

    @staticmethod
    def _xml_find_text(
        root: ET.Element,
        names: Iterable[str],
    ) -> str | None:
        """
        Find the first non-empty text element with one of the supplied names.
        """

        names = {
            name.lower()
            for name in names
        }

        for element in root.iter():

            if (
                NiktoCollector._local_name(
                    element.tag
                ).lower()
                not in names
            ):
                continue

            if element.text:
                text = element.text.strip()

                if text:
                    return text

        return None

    @staticmethod
    def _local_name(
        value: str,
    ) -> str:
        """
        Return an XML local element name without a namespace.
        """

        value = str(
            value
        )

        if "}" in value:
            return value.rsplit(
                "}",
                1,
            )[-1]

        if ":" in value:
            return value.rsplit(
                ":",
                1,
            )[-1]

        return value

    ###########################################################################
    # Plain-Text Parsing
    ###########################################################################

    def _parse_plain_text(
        self,
        content: str,
    ) -> list[dict[str, Any]]:
        """
        Parse standard line-oriented Nikto output.

        Nikto commonly emits findings using lines beginning with:

            +

        The parser preserves the complete original line as evidence and uses
        conservative heuristics for URL, status and identifier extraction.
        """

        records: list[dict[str, Any]] = []

        current_target: str | None = None
        current_host: str | None = None

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            urls = _HTTP_URL_PATTERN.findall(
                stripped
            )

            if urls:
                current_target = urls[0]

            host_match = re.search(
                r"Target\s*:\s*(.+)",
                stripped,
                re.IGNORECASE,
            )

            if host_match:
                current_host = host_match.group(
                    1
                ).strip()

            if not stripped.startswith(
                "+"
            ):
                continue

            finding_text = stripped[
                1:
            ].strip()

            if not finding_text:
                continue

            record: dict[str, Any] = {
                "description": finding_text,
                "raw": stripped,
            }

            if current_target:
                record[
                    "url"
                ] = current_target

            if current_host:
                record[
                    "host"
                ] = current_host

            identifiers = self._extract_identifiers(
                finding_text
            )

            if identifiers:
                record[
                    "identifiers"
                ] = identifiers

            status_match = _HTTP_STATUS_PATTERN.search(
                finding_text
            )

            if status_match:
                record[
                    "status_code"
                ] = int(
                    status_match.group(
                        1
                    )
                )

            severity_match = _SEVERITY_PATTERN.search(
                finding_text
            )

            if severity_match:
                record[
                    "severity"
                ] = severity_match.group(
                    1
                )

            records.append(
                record
            )

        return records

    ###########################################################################
    # Record Normalization
    ###########################################################################

    def _normalize_record(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """
        Normalize a raw Nikto record into a common internal representation.
        """

        description = self._first_text(
            record,
            (
                "description",
                "message",
                "finding",
                "title",
                "name",
                "text",
                "osvdb",
            ),
        )

        if not description:
            description = self._first_text(
                record,
                (
                    "raw",
                ),
            )

        if not description:
            return None

        url = self._record_url(
            record
        )

        host = self._first_text(
            record,
            (
                "host",
                "hostname",
                "target",
            ),
        )

        if not host and url:
            host = self._extract_host(
                url
            )

        identifier_values = []

        for key in (
            "id",
            "identifier",
            "osvdb",
            "osvdb_id",
            "cve",
            "cves",
            "identifiers",
        ):
            if key in record:
                identifier_values.append(
                    record.get(
                        key
                    )
                )

        identifiers = self._normalize_identifiers(
            identifier_values
        )

        cves = [
            identifier
            for identifier in identifiers
            if identifier.upper().startswith(
                "CVE-"
            )
        ]

        osvdb = [
            identifier
            for identifier in identifiers
            if identifier.upper().startswith(
                "OSVDB"
            )
        ]

        severity = self._normalize_severity(
            self._first_text(
                record,
                (
                    "severity",
                    "risk",
                ),
            )
        )

        observation_type = self._classify_finding(
            description,
            record,
        )

        title = self._build_title(
            description,
            observation_type,
        )

        evidence = {
            "raw_record": dict(
                record
            ),
        }

        for key in (
            "uri",
            "url",
            "host",
            "method",
            "status_code",
            "osvdb",
            "osvdb_id",
            "id",
            "identifier",
            "cve",
            "cves",
            "references",
            "raw",
        ):
            if key in record:
                evidence[
                    key
                ] = record.get(
                    key
                )

        return {
            "observation_type": observation_type,
            "title": title,
            "description": description,
            "url": url,
            "host": host,
            "identifier": (
                identifiers[0]
                if identifiers
                else ""
            ),
            "identifiers": identifiers,
            "cves": cves,
            "osvdb": osvdb,
            "severity": severity,
            "evidence": evidence,
            "raw_record": dict(
                record
            ),
        }

    ###########################################################################
    # Finding Classification
    ###########################################################################

    @staticmethod
    def _classify_finding(
        description: str,
        record: Mapping[str, Any],
    ) -> str:
        """
        Classify a Nikto result into one of ScopeForgeX's supported
        observation types.
        """

        text = (
            description
            + " "
            + " ".join(
                str(
                    value
                )
                for value in record.values()
                if value is not None
            )
        ).lower()

        if any(
            token in text
            for token in (
                "vulnerab",
                "cve-",
                "remote code",
                "code execution",
                "injection",
                "outdated",
                "obsolete",
                "known security",
            )
        ):
            return OBSERVATION_SERVER_VULNERABILITY

        if any(
            token in text
            for token in (
                "config",
                "enabled",
                "disabled",
                "http method",
                "options method",
                "trace",
                "directory listing",
                "server header",
                "security header",
            )
        ):
            return OBSERVATION_MISCONFIGURATION

        if any(
            token in text
            for token in (
                "file",
                "backup",
                "backup file",
                ".bak",
                ".old",
                ".zip",
                ".tar",
                ".gz",
                ".conf",
                ".config",
                ".env",
                "source code",
                "disclosure",
                "exposed",
            )
        ):
            return OBSERVATION_EXPOSED_FILE

        return OBSERVATION_WEB_SERVER_ISSUE

    @staticmethod
    def _build_title(
        description: str,
        observation_type: str,
    ) -> str:
        """
        Produce a concise title from a Nikto finding description.
        """

        text = description.strip()

        if len(text) <= 160:
            return text

        return (
            text[:157].rstrip()
            + "..."
        )

    ###########################################################################
    # Observation Construction
    ###########################################################################

    def _build_observation(
        self,
        record: Mapping[str, Any],
        *,
        target: str | None,
        source: str,
    ) -> CollectorObservation:
        """
        Convert a normalized Nikto record into a CollectorObservation.
        """

        url = self._optional_text(
            record.get(
                "url"
            )
        )

        host = self._optional_text(
            record.get(
                "host"
            )
        )

        if not host and url:
            host = self._extract_host(
                url
            )

        port = (
            self._extract_port(
                url
            )
            if url
            else None
        )

        severity = self._normalize_severity(
            record.get(
                "severity"
            )
        )

        confidence = _CONFIDENCE_BY_SEVERITY.get(
            severity,
            "informational",
        )

        metadata = {
            "source": source,
            "severity": severity,
            "identifiers": list(
                record.get(
                    "identifiers",
                    [],
                )
            ),
            "cves": list(
                record.get(
                    "cves",
                    [],
                )
            ),
            "osvdb": list(
                record.get(
                    "osvdb",
                    [],
                )
            ),
        }

        return CollectorObservation(
            observation_type=record[
                "observation_type"
            ],
            value=(
                url
                or record.get(
                    "title"
                )
                or record.get(
                    "identifier"
                )
                or "Nikto web-server issue"
            ),
            target=target,
            host=host,
            port=port,
            url=url,
            description=record.get(
                "description"
            ),
            evidence=record.get(
                "evidence"
            ),
            source_tool=TOOL_NAME,
            detection_method=(
                "Nikto web-server assessment"
            ),
            confidence=confidence,
            metadata=metadata,
        )

    ###########################################################################
    # Identifier Helpers
    ###########################################################################

    @staticmethod
    def _extract_identifiers(
        value: str,
    ) -> list[str]:
        """
        Extract CVE, OSVDB and Nikto-like identifiers from text.
        """

        result: list[str] = []

        for pattern in (
            _CVE_PATTERN,
            _OSVDB_PATTERN,
        ):
            result.extend(
                match.upper()
                for match in pattern.findall(
                    value
                )
            )

        return NiktoCollector._unique_strings(
            result
        )

    @staticmethod
    def _normalize_identifiers(
        values: Iterable[Any],
    ) -> list[str]:
        """
        Normalize identifiers from scalar and collection values.
        """

        result: list[str] = []

        for value in values:

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):
                result.extend(
                    NiktoCollector._extract_identifiers(
                        value
                    )
                )
                continue

            if isinstance(
                value,
                Iterable,
            ) and not isinstance(
                value,
                Mapping,
            ):
                for item in value:
                    result.extend(
                        NiktoCollector._normalize_identifiers(
                            [
                                item
                            ]
                        )
                    )
                continue

            result.extend(
                NiktoCollector._extract_identifiers(
                    str(
                        value
                    )
                )
            )

        return NiktoCollector._unique_strings(
            result
        )

    @staticmethod
    def _unique_strings(
        values: Iterable[Any],
    ) -> list[str]:
        """
        Return unique non-empty strings in input order.
        """

        result: list[str] = []

        for value in values:
            normalized = str(
                value
            ).strip()

            if (
                normalized
                and normalized not in result
            ):
                result.append(
                    normalized
                )

        return result

    ###########################################################################
    # General Helpers
    ###########################################################################

    @staticmethod
    def _first_text(
        mapping: Mapping[str, Any],
        keys: Iterable[str],
    ) -> str | None:
        """
        Return the first non-empty textual field from a mapping.
        """

        for key in keys:

            value = mapping.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):
                normalized = value.strip()

                if normalized:
                    return normalized

            elif value:
                return str(
                    value
                ).strip()

        return None

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """
        Normalize a Nikto severity value.

        Nikto output does not consistently expose a formal severity for every
        result. Missing or unknown values therefore become informational.
        """

        if value is None:
            return "informational"

        normalized = str(
            value
        ).strip().lower()

        return _SEVERITY_ALIASES.get(
            normalized,
            "informational",
        )

    @staticmethod
    def _optional_text(
        value: Any,
    ) -> str | None:
        """
        Normalize optional text.
        """

        if value is None:
            return None

        value = str(
            value
        ).strip()

        return value or None

    ###########################################################################
    # URL / Host Helpers
    ###########################################################################

    @staticmethod
    def _record_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a URL from a Nikto record.
        """

        for key in (
            "url",
            "uri",
            "matched-at",
            "matched_at",
            "endpoint",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ):
                value = value.strip()

                if value.startswith(
                    (
                        "http://",
                        "https://",
                    )
                ):
                    return value

        for value in record.values():

            if not isinstance(
                value,
                str,
            ):
                continue

            match = _HTTP_URL_PATTERN.search(
                value
            )

            if match:
                return match.group(
                    0
                )

        return None

    @staticmethod
    def _extract_host(
        value: str,
    ) -> str | None:
        """
        Extract the hostname from a URL or host-like value.
        """

        try:
            parsed = urlparse(
                value
            )

        except ValueError:
            return None

        if parsed.hostname:
            return parsed.hostname

        return value or None

    @staticmethod
    def _extract_port(
        url: str,
    ) -> int | None:
        """
        Extract an explicit or effective HTTP(S) port.
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
    "NiktoCollector",
]
