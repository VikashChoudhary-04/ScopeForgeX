"""
ScopeForgeX dig Collector
=========================

Collector for the ``dig`` DNS inspection utility.

The collector converts deterministic ``dig`` output into normalized
ScopeForgeX Finding objects.

Primary assessment capability
-----------------------------

    DNS inspection

Supported DNS observations
---------------------------

- A records
- AAAA records
- CNAME records
- MX records
- NS records
- TXT records
- SOA records

Finding categories
------------------

- DNS_RECORD
- DNS_CONFIGURATION

Design Principles
-----------------

- The collector only parses already-collected ``dig`` output.
- It never performs network requests itself.
- Command execution remains the responsibility of the execution layer.
- Raw output must remain available to the assessment evidence layer.
- Every parsed observation becomes a canonical Finding.
- Malformed records are ignored rather than producing fabricated findings.
- Parsing is deterministic.
- Source-tool attribution is preserved.
- The collector does not classify DNS observations as vulnerabilities.
- DNS findings remain compatible with correlation, deduplication and reporting.

Expected input
--------------

The collector accepts raw ``dig`` output for a single DNS query.

Example::

    ; <<>> DiG 9.18 <<>> example.com A
    ;; ANSWER SECTION:
    example.com.        300     IN      A       93.184.216.34

The collector may also parse output containing multiple records, such as
the result of a query against a broader DNS record set.

v1.3.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
)
from scopeforgex.models.finding import Finding


###############################################################################
# Constants
###############################################################################


SOURCE_TOOL = "dig"
DETECTION_METHOD = "DNS Record Inspection"

CATEGORY_DNS_RECORD = "DNS_RECORD"
CATEGORY_DNS_CONFIGURATION = "DNS_CONFIGURATION"

SUPPORTED_RECORD_TYPES = {
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "PTR",
    "SRV",
    "CAA",
}

_CONFIGURATION_RECORD_TYPES = {
    "MX",
    "NS",
    "SOA",
    "CAA",
}

_FINDING_ID_PREFIX = "SF-DIG-"


###############################################################################
# Helpers
###############################################################################


def _text(value: Any) -> str:
    """
    Convert a value to normalized text.
    """

    if value is None:
        return ""

    return str(value).strip()


def _normalize_name(value: str) -> str:
    """
    Normalize a DNS name.

    DNS names are case-insensitive. A trailing root dot is removed so that
    equivalent names produce deterministic finding identities.
    """

    value = _text(value).lower()

    if value == ".":
        return ""

    return value.rstrip(".")


def _normalize_record_type(value: str) -> str:
    """
    Normalize a DNS record type.
    """

    return _text(value).upper()


def _normalize_value(
    record_type: str,
    value: str,
) -> str:
    """
    Normalize a DNS record value while preserving meaningful content.
    """

    value = _text(value)

    if record_type in {
        "A",
        "AAAA",
        "CNAME",
        "PTR",
        "NS",
    }:
        return value.rstrip(".").lower()

    if record_type == "MX":
        parts = value.split()

        if len(parts) >= 2:
            preference = parts[0]
            exchange = parts[1].rstrip(".").lower()

            return f"{preference} {exchange}"

    if record_type == "SRV":
        parts = value.split()

        if len(parts) >= 4:
            priority = parts[0]
            weight = parts[1]
            port = parts[2]
            target = parts[3].rstrip(".").lower()

            return (
                f"{priority} "
                f"{weight} "
                f"{port} "
                f"{target}"
            )

    if record_type == "TXT":
        return value

    return value.rstrip(".").lower()


def _is_record_type(value: str) -> bool:
    """
    Determine whether a token represents a supported DNS record type.
    """

    return _normalize_record_type(
        value
    ) in SUPPORTED_RECORD_TYPES


###############################################################################
# DNS Record
###############################################################################


class DNSRecord:
    """
    Internal normalized representation of a DNS record.
    """

    __slots__ = (
        "name",
        "record_type",
        "ttl",
        "value",
        "class_name",
    )

    def __init__(
        self,
        *,
        name: str,
        record_type: str,
        ttl: int | None,
        value: str,
        class_name: str = "IN",
    ) -> None:
        self.name = _normalize_name(name)
        self.record_type = _normalize_record_type(
            record_type
        )
        self.ttl = ttl
        self.value = _normalize_value(
            self.record_type,
            value,
        )
        self.class_name = (
            _text(class_name).upper()
            or "IN"
        )


###############################################################################
# Collector
###############################################################################


class DigCollector(CollectorBase):
    """
    Parse ``dig`` output into canonical ScopeForgeX findings.

    The collector does not execute ``dig``. Command construction and process
    execution belong to the tool adapter/execution layer.
    """

    name = "dig"
    tool = "dig"

    description = (
        "Parse deterministic dig DNS inspection output into normalized "
        "ScopeForgeX findings."
    )

    supported_record_types = frozenset(
        SUPPORTED_RECORD_TYPES
    )

    ###########################################################################
    # Canonical Collector Contract
    ###########################################################################

    @staticmethod
    def _finding_to_observation(
        finding: Any,
    ) -> CollectorObservation:
        """
        Convert a canonical Finding into a CollectorObservation.
        """

        data = (
            finding.as_dict()
            if hasattr(
                finding,
                "as_dict",
            )
            else finding
        )

        if not isinstance(
            data,
            Mapping,
        ):
            data = {}

        return CollectorObservation(
            observation_type=str(
                data.get(
                    "category",
                    data.get(
                        "type",
                        "finding",
                    ),
                )
            ),
            value=(
                data.get("value")
                or data.get("host")
                or data.get("url")
                or data.get("title")
            ),
            title=str(
                data.get("title", "")
            ),
            description=str(
                data.get("description", "")
            ),
            impact=str(
                data.get("impact", "")
            ),
            remediation=str(
                data.get("remediation", "")
            ),
            severity=str(
                data.get(
                    "severity",
                    "Informational",
                )
            ),
            confidence=str(
                data.get(
                    "confidence",
                    "Informational",
                )
            ),
            status=str(
                data.get(
                    "status",
                    "Pending",
                )
            ),
            target=data.get("target"),
            host=data.get("host"),
            port=data.get("port"),
            url=data.get("url"),
            parameter=data.get("parameter"),
            evidence=data.get("evidence"),
            source_tool=str(
                data.get(
                    "source_tool",
                    "",
                )
            ),
            detection_method=str(
                data.get(
                    "detection_method",
                    "",
                )
            ),
            cwe=data.get("cwe"),
            cve=data.get("cve"),
            references=list(
                data.get(
                    "references",
                    [],
                )
                or []
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
                or {}
            ),
        )

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse an already-completed dig execution result.

        No network requests or command execution occur here.
        """

        context = dict(ctx or {})
        output = ""

        if isinstance(
            execution_result,
            Mapping,
        ):
            output = (
                execution_result.get(
                    "stdout",
                    "",
                )
                or execution_result.get(
                    "output",
                    "",
                )
                or ""
            )
        else:
            output = getattr(
                execution_result,
                "stdout",
                "",
            ) or ""

        target = str(
            context.get(
                "target",
                "",
            )
            or ""
        ).strip()

        query_type = context.get(
            "query_type"
        )

        metadata = context.get(
            "metadata",
            {}
        )

        findings = self.collect_findings(
            str(output),
            target=target,
            query_type=(
                str(query_type)
                if query_type
                else None
            ),
            metadata=(
                metadata
                if isinstance(
                    metadata,
                    Mapping,
                )
                else None
            ),
        )

        return [
            self._finding_to_observation(
                finding
            )
            for finding in findings
        ]

    ###########################################################################
    # Existing Finding Collection API
    ###########################################################################

    def collect_findings(
        self,
        output: str,
        *,
        target: str = "",
        query_type: str | None = None,
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Parse raw ``dig`` output into canonical Finding objects.
        """

        if output is None:
            return []

        if not isinstance(
            output,
            str,
        ):
            raise TypeError(
                "DigCollector.collect_findings() expects textual dig output."
            )

        records = self._parse_output(
            output
        )

        if not records:
            return []

        target = _text(
            target
        )

        query_type = (
            _normalize_record_type(
                query_type
            )
            if query_type
            else ""
        )

        observation_time = (
            timestamp
            if timestamp is not None
            else datetime.now(
                timezone.utc
            )
        )

        findings: list[Finding] = []

        seen: set[
            tuple[str, str, str]
        ] = set()

        for record in records:

            identity = (
                record.name,
                record.record_type,
                record.value,
            )

            if identity in seen:
                continue

            seen.add(
                identity
            )

            findings.append(
                self._record_to_finding(
                    record,
                    target=target,
                    query_type=query_type,
                    timestamp=observation_time,
                    metadata=metadata,
                )
            )

        return findings

    def _parse_output(
        self,
        output: str,
    ) -> list[DNSRecord]:
        """
        Parse raw ``dig`` output into normalized DNSRecord objects.
        """

        if output is None:
            return []

        if not isinstance(
            output,
            str,
        ):
            raise TypeError(
                "DigCollector._parse_output() expects textual dig output."
            )

        records: list[DNSRecord] = []
        section = ""

        for raw_line in output.splitlines():

            line = raw_line.strip()

            if not line:
                continue

            if line.startswith(
                ";;"
            ):
                section = self._section_from_header(
                    line
                )
                continue

            if line.startswith(
                ";"
            ):
                continue

            record = self._parse_record_line(
                line
            )

            if record is None:
                continue

            if section and section not in {
                "ANSWER",
                "AUTHORITY",
                "ADDITIONAL",
            }:
                continue

            records.append(
                record
            )

        return records

    def collect_many(
        self,
        outputs: Iterable[str],
        *,
        target: str = "",
        query_type: str | None = None,
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Parse multiple ``dig`` outputs.
        """

        if outputs is None:
            return []

        findings: list[Finding] = []

        seen: set[
            tuple[str, str, str]
        ] = set()

        for output in outputs:

            current = self.collect_findings(
                output,
                target=target,
                query_type=query_type,
                timestamp=timestamp,
                metadata=metadata,
            )

            for finding in current:

                identity = self._finding_identity(
                    finding
                )

                if identity in seen:
                    continue

                seen.add(
                    identity
                )

                findings.append(
                    finding
                )

        return findings

    ###########################################################################
    # Record Parsing
    ###########################################################################

    @staticmethod
    def _section_from_header(
        line: str,
    ) -> str:
        normalized = line.upper()

        if "ANSWER SECTION:" in normalized:
            return "ANSWER"

        if "AUTHORITY SECTION:" in normalized:
            return "AUTHORITY"

        if "ADDITIONAL SECTION:" in normalized:
            return "ADDITIONAL"

        return ""

    @classmethod
    def _parse_record_line(
        cls,
        line: str,
    ) -> DNSRecord | None:
        tokens = line.split()

        if len(tokens) < 4:
            return None

        record_type_index = -1

        for index, token in enumerate(
            tokens
        ):
            if _is_record_type(
                token
            ):
                record_type_index = index
                break

        if record_type_index < 1:
            return None

        record_type = _normalize_record_type(
            tokens[
                record_type_index
            ]
        )

        name = tokens[0]
        ttl: int | None = None
        class_name = "IN"

        preceding = tokens[
            1:record_type_index
        ]

        for token in preceding:

            if token.isdigit():
                ttl = int(
                    token
                )

            elif token.upper() in {
                "IN",
                "CH",
                "HS",
            }:
                class_name = token.upper()

        value_tokens = tokens[
            record_type_index + 1:
        ]

        if not value_tokens:
            return None

        value = cls._join_value(
            record_type,
            value_tokens,
        )

        if not value:
            return None

        return DNSRecord(
            name=name,
            record_type=record_type,
            ttl=ttl,
            value=value,
            class_name=class_name,
        )

    @staticmethod
    def _join_value(
        record_type: str,
        tokens: list[str],
    ) -> str:
        if record_type == "TXT":
            return " ".join(
                tokens
            )

        return " ".join(
            tokens
        )

    ###########################################################################
    # Finding Conversion
    ###########################################################################

    @classmethod
    def _record_to_finding(
        cls,
        record: DNSRecord,
        *,
        target: str,
        query_type: str,
        timestamp: datetime,
        metadata: Mapping[str, Any] | None,
    ) -> Finding:

        category = (
            CATEGORY_DNS_CONFIGURATION
            if record.record_type
            in _CONFIGURATION_RECORD_TYPES
            else CATEGORY_DNS_RECORD
        )

        title = (
            f"DNS {record.record_type} Record: "
            f"{record.name}"
        )

        description = (
            f"The DNS record for {record.name} contains a "
            f"{record.record_type} record with value "
            f"{record.value}."
        )

        evidence: dict[str, Any] = {
            "record_name": record.name,
            "record_type": record.record_type,
            "record_value": record.value,
            "class": record.class_name,
        }

        if record.ttl is not None:
            evidence["ttl"] = record.ttl

        if query_type:
            evidence["query_type"] = query_type

        finding_metadata: dict[str, Any] = {}

        if metadata is not None:
            finding_metadata.update(
                dict(metadata)
            )

        finding_metadata.update(
            {
                "collector": cls.name,
                "dns_record_type": record.record_type,
                "dns_record_name": record.name,
            }
        )

        if record.ttl is not None:
            finding_metadata[
                "dns_ttl"
            ] = record.ttl

        finding_id = cls._finding_id(
            record,
            target=target,
        )

        finding_data = {
            "title": title,
            "category": category,
            "severity": "Informational",
            "confidence": "High",
            "target": target,
            "host": record.name or None,
            "port": None,
            "url": None,
            "parameter": None,
            "description": description,
            "evidence": evidence,
            "source_tool": SOURCE_TOOL,
            "detection_method": DETECTION_METHOD,
            "timestamp": timestamp,
            "references": [],
            "impact": "DNS information discovered during assessment.",
            "remediation": (
                "Review the DNS record and confirm that it is intentional "
                "and consistent with the assessment scope."
            ),
            "status": "detected",
            "metadata": finding_metadata,
        }

        return Finding.from_mapping(
            finding_data,
            finding_id=finding_id,
        )

    ###########################################################################
    # Finding Identity
    ###########################################################################

    @staticmethod
    def _finding_id(
        record: DNSRecord,
        *,
        target: str,
    ) -> str:
        import hashlib

        identity = (
            f"{_normalize_name(target)}|"
            f"{record.name}|"
            f"{record.record_type}|"
            f"{record.value}"
        )

        digest = hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()[:12]

        return (
            f"{_FINDING_ID_PREFIX}"
            f"{digest.upper()}"
        )

    @staticmethod
    def _finding_identity(
        finding: Finding,
    ) -> tuple[str, str, str]:
        metadata = getattr(
            finding,
            "metadata",
            {},
        )

        if not isinstance(
            metadata,
            Mapping,
        ):
            metadata = {}

        evidence = getattr(
            finding,
            "evidence",
            {},
        )

        if not isinstance(
            evidence,
            Mapping,
        ):
            evidence = {}

        return (
            _text(
                metadata.get(
                    "dns_record_name",
                )
            ).lower(),
            _text(
                metadata.get(
                    "dns_record_type",
                )
            ).upper(),
            _text(
                evidence.get(
                    "record_value",
                    "",
                )
            ),
        )


###############################################################################
# Convenience API
###############################################################################


def collect_dig_findings(
    output: str,
    *,
    target: str = "",
    query_type: str | None = None,
    timestamp: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> list[Finding]:

    return DigCollector().collect_findings(
        output,
        target=target,
        query_type=query_type,
        timestamp=timestamp,
        metadata=metadata,
    )


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "SOURCE_TOOL",
    "DETECTION_METHOD",
    "CATEGORY_DNS_RECORD",
    "CATEGORY_DNS_CONFIGURATION",
    "SUPPORTED_RECORD_TYPES",
    "DNSRecord",
    "DigCollector",
    "collect_dig_findings",
]
