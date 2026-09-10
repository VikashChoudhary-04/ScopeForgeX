"""
ScopeForgeX dig Collector
=========================

Collector for the ``dig`` DNS inspection utility.

The collector converts deterministic ``dig`` output into normalized
ScopeForgeX observations.

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
- PTR records
- SRV records
- CAA records

Observation categories
----------------------

- DNS_RECORD
- DNS_CONFIGURATION

Design Principles
-----------------

- The collector only parses already-collected ``dig`` output.
- It never performs network requests itself.
- Command execution remains the responsibility of the execution layer.
- Raw output must remain available to the assessment evidence layer.
- DNS records are attack-surface observations, not vulnerabilities by
  themselves.
- Malformed records are ignored rather than producing fabricated findings.
- Parsing is deterministic.
- Source-tool attribution is preserved.
- DNS observations remain compatible with correlation, deduplication
  and reporting.
- The legacy ``collect_findings()`` API is retained for compatibility
  with callers that explicitly request Finding objects.

Expected input
--------------

The collector accepts raw ``dig`` output for a single DNS query.

Example::

    ; <<>> DiG 9.18 <<>> example.com A
    ;; ANSWER SECTION:
    example.com.        300     IN      A       93.184.216.34

The collector may also parse output containing multiple records, such as
the result of a query against a broader DNS record set.

v1.4.0
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
    equivalent names produce deterministic identities.
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

    return (
        _normalize_record_type(value)
        in SUPPORTED_RECORD_TYPES
    )


def _record_category(record_type: str) -> str:
    """
    Return the attack-surface observation category for a DNS record.

    DNS_CONFIGURATION is used for record types that describe mail,
    delegation, authority or certificate-authority configuration.
    Other supported DNS records remain DNS_RECORD observations.
    """

    normalized = _normalize_record_type(record_type)

    if normalized in _CONFIGURATION_RECORD_TYPES:
        return CATEGORY_DNS_CONFIGURATION

    return CATEGORY_DNS_RECORD


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
    Parse ``dig`` output into canonical ScopeForgeX observations.

    DNS records discovered by ``dig`` are attack-surface observations.
    They are not security vulnerabilities merely because they exist.

    The collector does not execute ``dig``. Command construction and process
    execution belong to the tool adapter/execution layer.
    """

    name = "dig"
    tool = "dig"

    description = (
        "Parse deterministic dig DNS inspection output into normalized "
        "ScopeForgeX attack-surface observations."
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
        Convert a legacy canonical Finding into an attack-surface
        CollectorObservation.

        This compatibility path intentionally marks the resulting
        observation as non-vulnerability data.
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

        category = str(
            data.get(
                "category",
                data.get(
                    "type",
                    CATEGORY_DNS_RECORD,
                ),
            )
            or CATEGORY_DNS_RECORD
        ).upper()

        if category not in {
            CATEGORY_DNS_RECORD,
            CATEGORY_DNS_CONFIGURATION,
        }:
            category = CATEGORY_DNS_RECORD

        metadata = dict(
            data.get(
                "metadata",
                {},
            )
            or {}
        )

        metadata.update(
            {
                "collector": DigCollector.name,
                "observation_only": True,
                "is_security_finding": False,
                "dns_record_type": (
                    data.get(
                        "metadata",
                        {},
                    ).get(
                        "dns_record_type",
                        "",
                    )
                    if isinstance(
                        data.get(
                            "metadata",
                            {},
                        ),
                        Mapping,
                    )
                    else ""
                ),
            }
        )

        return CollectorObservation(
            observation_type=category,
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
            severity="Informational",
            confidence=str(
                data.get(
                    "confidence",
                    "High",
                )
            ),
            status=str(
                data.get(
                    "status",
                    "detected",
                )
            ),
            target=data.get("target"),
            host=data.get("host"),
            port=data.get("port"),
            url=data.get("url"),
            parameter=None,
            evidence=data.get("evidence"),
            source_tool=SOURCE_TOOL,
            detection_method=DETECTION_METHOD,
            cwe=None,
            cve=None,
            references=list(
                data.get(
                    "references",
                    [],
                )
                or []
            ),
            metadata=metadata,
        )

    @classmethod
    def _record_to_observation(
        cls,
        record: DNSRecord,
        *,
        target: str,
        query_type: str,
        metadata: Mapping[str, Any] | None,
    ) -> CollectorObservation:
        """
        Convert a normalized DNS record into a canonical attack-surface
        observation.
        """

        category = _record_category(
            record.record_type
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

        observation_metadata: dict[str, Any] = {}

        if metadata is not None:
            observation_metadata.update(
                dict(metadata)
            )

        observation_metadata.update(
            {
                "collector": cls.name,
                "observation_only": True,
                "is_security_finding": False,
                "dns_record_type": record.record_type,
                "dns_record_name": record.name,
            }
        )

        if record.ttl is not None:
            observation_metadata[
                "dns_ttl"
            ] = record.ttl

        title = (
            f"DNS {record.record_type} Record: "
            f"{record.name}"
        )

        description = (
            f"The DNS inspection discovered a "
            f"{record.record_type} record for "
            f"{record.name} with value "
            f"{record.value}."
        )

        return CollectorObservation(
            observation_type=category,
            value=record.value,
            title=title,
            description=description,
            impact=(
                "DNS attack-surface information discovered "
                "during assessment."
            ),
            remediation=(
                "Review the DNS record and confirm that it is "
                "intentional and consistent with the assessment scope."
            ),
            severity="Informational",
            confidence="High",
            status="detected",
            target=target or None,
            host=record.name or None,
            port=None,
            url=None,
            parameter=None,
            evidence=evidence,
            source_tool=SOURCE_TOOL,
            detection_method=DETECTION_METHOD,
            cwe=None,
            cve=None,
            references=[],
            metadata=observation_metadata,
        )

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse an already-completed dig execution result.

        The canonical collector path returns DNS records as
        CollectorObservation objects rather than vulnerability Findings.

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

        query_type_normalized = (
            _normalize_record_type(
                str(query_type)
            )
            if query_type
            else ""
        )

        metadata = context.get(
            "metadata",
            {}
        )

        return self.collect_observations(
            str(output),
            target=target,
            query_type=(
                query_type_normalized
                if query_type_normalized
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

    ###########################################################################
    # Canonical Observation Collection API
    ###########################################################################

    def collect_observations(
        self,
        output: str,
        *,
        target: str = "",
        query_type: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[CollectorObservation]:
        """
        Parse raw ``dig`` output into attack-surface observations.

        DNS observations are explicitly marked as non-security findings.
        """

        if output is None:
            return []

        if not isinstance(
            output,
            str,
        ):
            raise TypeError(
                "DigCollector.collect_observations() expects "
                "textual dig output."
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

        observations: list[
            CollectorObservation
        ] = []

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

            observations.append(
                self._record_to_observation(
                    record,
                    target=target,
                    query_type=query_type,
                    metadata=metadata,
                )
            )

        return observations

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
        Parse raw ``dig`` output into legacy canonical Finding objects.

        This method is retained for backward compatibility with callers
        explicitly requesting the historical Finding representation.

        The canonical collector ``parse()`` path does not use this method;
        it returns CollectorObservation objects so DNS records are not
        automatically treated as security findings.
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
        Parse multiple ``dig`` outputs using the legacy Finding API.
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
    # Legacy Finding Conversion
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
        """
        Convert a DNS record into the historical Finding representation.

        This method exists only for the legacy ``collect_findings()`` API.
        The canonical ``parse()`` path uses ``_record_to_observation()``.
        """

        category = _record_category(
            record.record_type
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
                "observation_only": True,
                "is_security_finding": False,
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
            "impact": (
                "DNS information discovered during assessment."
            ),
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
# Convenience APIs
###############################################################################


def collect_dig_observations(
    output: str,
    *,
    target: str = "",
    query_type: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> list[CollectorObservation]:
    """
    Parse ``dig`` output into canonical attack-surface observations.
    """

    return DigCollector().collect_observations(
        output,
        target=target,
        query_type=query_type,
        metadata=metadata,
    )


def collect_dig_findings(
    output: str,
    *,
    target: str = "",
    query_type: str | None = None,
    timestamp: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> list[Finding]:
    """
    Legacy convenience API returning Finding objects.

    Prefer ``collect_dig_observations()`` for the canonical assessment path.
    """

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
    "collect_dig_observations",
    "collect_dig_findings",
]
