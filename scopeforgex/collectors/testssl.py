"""
ScopeForgeX testssl.sh Collector
================================

Parses testssl.sh output into structured ScopeForgeX observations.

testssl.sh is responsible for TLS/SSL security assessment.

Primary observations:

    TLS_CONFIGURATION
    WEAK_PROTOCOL
    WEAK_CIPHER
    CERTIFICATE_ISSUE
    TLS_VULNERABILITY

Architecture
------------

testssl.sh
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
TestSSLCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes testssl.sh.
- The collector never constructs testssl.sh commands.
- Raw testssl.sh output remains preserved in the ExecutionResult artifacts.
- JSON output is preferred when available.
- JSONL-style records are supported.
- Plain-text testssl.sh output is parsed conservatively.
- Duplicate observations are removed deterministically.
- Protocol and cipher findings are represented separately.
- Certificate findings retain certificate-related evidence.
- The collector does not assign final risk.
- Detection does not imply manual confirmation.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "testssl.sh"

OBSERVATION_TLS_CONFIGURATION = "TLS_CONFIGURATION"
OBSERVATION_WEAK_PROTOCOL = "WEAK_PROTOCOL"
OBSERVATION_WEAK_CIPHER = "WEAK_CIPHER"
OBSERVATION_CERTIFICATE_ISSUE = "CERTIFICATE_ISSUE"
OBSERVATION_TLS_VULNERABILITY = "TLS_VULNERABILITY"


###############################################################################
# Collector
###############################################################################


class TestSSLCollector(CollectorBase):
    """
    Collect structured TLS security observations from testssl.sh output.

    Supported input forms include:

        - testssl.sh JSON output
        - JSON arrays
        - JSONL records
        - plain-text testssl.sh output

    The collector is intentionally parser-only. It does not perform network
    requests and does not attempt to validate TLS findings independently.
    """

    name = "testssl"
    tool = "testssl.sh"

    description = (
        "Parses testssl.sh TLS assessment output into structured "
        "configuration, protocol, cipher, certificate and vulnerability "
        "observations."
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
        Parse testssl.sh output into structured observations.

        JSON output is handled as structured evidence. Plain-text output is
        parsed using conservative category and finding heuristics.
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

            records = self._iter_records(
                content
            )

            for record in records:

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

                    key = (
                        observation_type,
                        value.lower(),
                        target,
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
                            host=parsed.get(
                                "host"
                            ),
                            port=parsed.get(
                                "port"
                            ),
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
        Return available testssl.sh evidence as labelled text.

        Artifact files are processed before stdout because persistent
        execution artifacts are the preferred source of raw evidence.
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
        Convert raw testssl.sh content into logical records.

        A complete JSON document is parsed first. When that fails, individual
        JSONL records and plain-text lines are processed.
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
                    record = json.loads(
                        stripped
                    )

                except json.JSONDecodeError:
                    record = None

                if isinstance(
                    record,
                    Mapping,
                ):
                    records.append(
                        record
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
        Normalize a raw record into one or more TLS observations.
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
        Parse a structured testssl.sh record.

        The JSON schema of testssl.sh can vary between versions and options,
        so field names are interpreted conservatively.
        """

        observations: list[dict[str, Any]] = []

        host = self._extract_host(
            record
        )

        port = self._extract_port(
            record
        )

        category = self._combined_text(
            record,
            (
                "id",
                "finding",
                "severity",
                "category",
                "section",
                "finding_id",
                "title",
            ),
        )

        text = self._combined_text(
            record,
            (
                "finding",
                "title",
                "severity",
                "status",
                "finding_id",
                "id",
                "cve",
                "cwe",
            ),
        )

        observation_type = self._classify_text(
            category,
            text,
        )

        if observation_type is not None:

            value = self._mapping_value(
                record,
                (
                    "finding",
                    "title",
                    "finding_id",
                    "id",
                    "status",
                ),
            )

            if value is None:
                value = text

            observations.append(
                {
                    "observation_type": (
                        observation_type
                    ),
                    "value": value,
                    "host": host,
                    "port": port,
                    "evidence": dict(
                        record
                    ),
                    "metadata": self._extract_mapping_metadata(
                        record
                    ),
                    "confidence": (
                        self._mapping_confidence(
                            record
                        )
                    ),
                }
            )

        protocol = self._mapping_value(
            record,
            (
                "protocol",
                "protocols",
                "tls_version",
                "ssl_version",
            ),
        )

        if protocol:

            protocol_text = str(
                protocol
            ).strip()

            protocol_type = (
                self._classify_protocol(
                    protocol_text,
                    text,
                )
            )

            if protocol_type:

                observations.append(
                    {
                        "observation_type": (
                            protocol_type
                        ),
                        "value": protocol_text,
                        "host": host,
                        "port": port,
                        "evidence": dict(
                            record
                        ),
                        "metadata": (
                            self._extract_mapping_metadata(
                                record
                            )
                        ),
                    }
                )

        cipher = self._mapping_value(
            record,
            (
                "cipher",
                "cipher_suite",
                "ciphers",
            ),
        )

        if cipher:

            cipher_text = str(
                cipher
            ).strip()

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_WEAK_CIPHER
                        if self._looks_weak_cipher(
                            cipher_text,
                            text,
                        )
                        else OBSERVATION_TLS_CONFIGURATION
                    ),
                    "value": cipher_text,
                    "host": host,
                    "port": port,
                    "evidence": dict(
                        record
                    ),
                    "metadata": (
                        self._extract_mapping_metadata(
                            record
                        )
                    ),
                }
            )

        certificate = self._mapping_value(
            record,
            (
                "certificate",
                "cert",
                "certificate_issue",
                "certificate_error",
            ),
        )

        if certificate:

            observations.append(
                {
                    "observation_type": (
                        OBSERVATION_CERTIFICATE_ISSUE
                    ),
                    "value": str(
                        certificate
                    ).strip(),
                    "host": host,
                    "port": port,
                    "evidence": dict(
                        record
                    ),
                    "metadata": (
                        self._extract_mapping_metadata(
                            record
                        )
                    ),
                }
            )

        return observations

    def _parse_text_record(
        self,
        line: str,
    ) -> list[dict[str, Any]]:
        """
        Parse one plain-text testssl.sh line.

        Only lines that contain recognizable TLS assessment terminology are
        converted into observations.
        """

        text = line.strip()

        if not text:
            return []

        observation_type = self._classify_text(
            text,
            text,
        )

        if observation_type is None:
            return []

        host = None
        port = None

        endpoint_match = re.search(
            r"https?://([^/\s:]+)(?::(\d+))?",
            text,
            flags=re.IGNORECASE,
        )

        if endpoint_match:

            host = endpoint_match.group(
                1
            )

            port_value = endpoint_match.group(
                2
            )

            if port_value:
                try:
                    port = int(
                        port_value
                    )
                except ValueError:
                    port = None

        value = self._extract_text_value(
            text,
            observation_type,
        )

        return [
            {
                "observation_type": observation_type,
                "value": value or text,
                "host": host,
                "port": port,
                "evidence": text,
                "metadata": {
                    "raw_line": text,
                },
            }
        ]

    ###########################################################################
    # Classification
    ###########################################################################

    @classmethod
    def _classify_text(
        cls,
        category: str,
        text: str,
    ) -> str | None:
        """
        Classify TLS evidence into the canonical observation categories.
        """

        combined = (
            f"{category} {text}"
        ).lower()

        if cls._contains_any(
            combined,
            (
                "certificate",
                "cert issue",
                "cert_problem",
                "cert problem",
                "hostname mismatch",
                "not trusted",
                "expired certificate",
                "self-signed",
            ),
        ):
            return OBSERVATION_CERTIFICATE_ISSUE

        if cls._contains_any(
            combined,
            (
                "heartbleed",
                "poodle",
                "beast",
                "crime",
                "breach",
                "freak",
                "logjam",
                "drown",
                "robot",
                "sweet32",
                "ccs injection",
                "renegotiation",
                "tls vulnerability",
                "ssl vulnerability",
            ),
        ):
            return OBSERVATION_TLS_VULNERABILITY

        if cls._contains_any(
            combined,
            (
                "cipher",
                "3des",
                "des-cbc",
                "rc4",
                "null cipher",
                "export cipher",
                "anonymous cipher",
                "weak cipher",
                "arcfour",
            ),
        ):
            return OBSERVATION_WEAK_CIPHER

        if cls._contains_any(
            combined,
            (
                "tlsv1.0",
                "tls 1.0",
                "tlsv1.1",
                "tls 1.1",
                "sslv2",
                "sslv3",
                "sslv3",
                "weak protocol",
                "deprecated protocol",
                "protocol",
            ),
        ):
            return OBSERVATION_WEAK_PROTOCOL

        if cls._contains_any(
            combined,
            (
                "tls",
                "ssl",
                "hsts",
                "ocsp",
                "alpn",
                "session resumption",
                "secure renegotiation",
                "compression",
                "http/2",
            ),
        ):
            return OBSERVATION_TLS_CONFIGURATION

        return None

    @staticmethod
    def _classify_protocol(
        protocol: str,
        context: str,
    ) -> str:
        """
        Classify a protocol value as weak or general TLS configuration.
        """

        combined = (
            f"{protocol} {context}"
        ).lower()

        weak_protocols = (
            "sslv2",
            "sslv3",
            "tlsv1.0",
            "tls 1.0",
            "tlsv1.1",
            "tls 1.1",
        )

        for value in weak_protocols:

            if value in combined:
                return OBSERVATION_WEAK_PROTOCOL

        return OBSERVATION_TLS_CONFIGURATION

    @staticmethod
    def _looks_weak_cipher(
        cipher: str,
        context: str,
    ) -> bool:
        """
        Return whether a cipher description contains known weak-cipher
        indicators.
        """

        combined = (
            f"{cipher} {context}"
        ).lower()

        indicators = (
            "3des",
            "des-cbc",
            "rc4",
            "arcfour",
            "null",
            "export",
            "anonymous",
            "anon-",
            "md5",
            "rc2",
            "40-bit",
            "56-bit",
            "sweet32",
        )

        return any(
            indicator in combined
            for indicator in indicators
        )

    @staticmethod
    def _contains_any(
        value: str,
        candidates: Iterable[str],
    ) -> bool:
        """
        Return whether a string contains one of the supplied terms.
        """

        return any(
            candidate in value
            for candidate in candidates
        )

    ###########################################################################
    # Text Value Extraction
    ###########################################################################

    @staticmethod
    def _extract_text_value(
        text: str,
        observation_type: str,
    ) -> str:
        """
        Extract a concise value from a plain-text finding line.
        """

        separators = (
            "|",
            ":",
        )

        for separator in separators:

            if separator not in text:
                continue

            parts = [
                part.strip()
                for part in text.split(
                    separator,
                    1,
                )
            ]

            if len(parts) == 2 and parts[1]:
                return parts[1]

        return text

    ###########################################################################
    # Mapping Helpers
    ###########################################################################

    @staticmethod
    def _mapping_value(
        record: Mapping[str, Any],
        keys: Iterable[str],
    ) -> Any:
        """
        Return the first meaningful mapping value.
        """

        for key in keys:

            if key not in record:
                continue

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
        Combine textual values from a structured testssl.sh record.
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
        Preserve an explicitly supplied confidence-like value when present.
        """

        for key in (
            "confidence",
            "severity",
        ):

            value = record.get(
                key
            )

            if value is None:
                continue

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

    @staticmethod
    def _extract_mapping_metadata(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve useful structured testssl.sh fields as metadata.
        """

        metadata: dict[str, Any] = {}

        for key in (
            "id",
            "finding_id",
            "severity",
            "status",
            "cve",
            "cwe",
            "severity",
            "ip",
            "port",
            "protocol",
            "cipher",
            "certificate",
            "section",
            "rating",
        ):

            if key in record:
                metadata[
                    key
                ] = record.get(
                    key
                )

        return metadata

    ###########################################################################
    # Host / Port Helpers
    ###########################################################################

    @staticmethod
    def _extract_host(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a hostname from structured testssl.sh evidence.
        """

        for key in (
            "host",
            "hostname",
            "fqdn",
            "server",
            "target",
            "ip",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                candidate = value.strip()

                if candidate.startswith(
                    (
                        "http://",
                        "https://",
                    )
                ):

                    match = re.match(
                        r"https?://([^/:]+)",
                        candidate,
                        flags=re.IGNORECASE,
                    )

                    if match:
                        return match.group(
                            1
                        ).lower()

                return candidate.lower()

        return None

    @staticmethod
    def _extract_port(
        record: Mapping[str, Any],
    ) -> int | None:
        """
        Extract a port from structured testssl.sh evidence.
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

        target = record.get(
            "target"
        )

        if isinstance(
            target,
            str,
        ):

            match = re.match(
                r"https?://[^/:]+:(\d+)",
                target,
                flags=re.IGNORECASE,
            )

            if match:

                try:
                    return int(
                        match.group(
                            1
                        )
                    )
                except ValueError:
                    pass

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
        evidence: Any = None,
        metadata: Mapping[str, Any] | None = None,
        confidence: str = "informational",
    ) -> CollectorObservation:
        """
        Build a canonical CollectorObservation.
        """

        detection_methods = {
            OBSERVATION_TLS_CONFIGURATION: (
                "testssl.sh TLS configuration assessment"
            ),
            OBSERVATION_WEAK_PROTOCOL: (
                "testssl.sh weak protocol detection"
            ),
            OBSERVATION_WEAK_CIPHER: (
                "testssl.sh weak cipher detection"
            ),
            OBSERVATION_CERTIFICATE_ISSUE: (
                "testssl.sh certificate assessment"
            ),
            OBSERVATION_TLS_VULNERABILITY: (
                "testssl.sh TLS vulnerability detection"
            ),
        }

        return CollectorObservation(
            observation_type=observation_type,
            value=value,
            target=target,
            host=host,
            port=port,
            evidence=evidence,
            source_tool=TOOL_NAME,
            detection_method=detection_methods.get(
                observation_type,
                "testssl.sh TLS assessment",
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
    "TestSSLCollector",
]
