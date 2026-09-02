"""
ScopeForgeX Amass Collector
============================

Collector for normalizing OWASP Amass output into the universal
ScopeForgeX Finding model.

Amass is used by ScopeForgeX as the primary broad attack-surface discovery
capability for:

- subdomain discovery
- DNS asset discovery
- host discovery
- infrastructure relationships

The collector is intentionally responsible only for converting Amass output
into structured findings.

Workflow
--------

    Amass
      |
      v
    Raw Output
      |
      v
    AmassCollector
      |
      v
    Normalized Finding objects
      |
      +--> SUBDOMAIN
      +--> DNS_ASSET
      +--> HOST

Design Principles
-----------------

- The collector never executes Amass.
- The collector never performs network requests.
- Raw Amass output remains the responsibility of the execution/evidence layer.
- The collector only parses and normalizes supplied output.
- Every emitted object is a canonical ScopeForgeX Finding.
- Duplicate observations are not removed here.
- Correlation and deduplication happen downstream.
- Parsing errors should not destroy successfully parsed findings.
- Amass source information is preserved.
- Findings remain traceable to the Amass detection method.
- JSON/JSONL output is preferred when supplied by Amass.
- Plain-text fallback parsing is supported for common Amass output.
- Malformed individual records are skipped rather than crashing the entire
  collection process.
- Collection is deterministic for identical input.

v1.3.0
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from scopeforgex.collectors.base import CollectorBase, CollectorObservation
from scopeforgex.models.finding import Finding


###############################################################################
# Constants
###############################################################################


SOURCE_TOOL = "Amass"

DETECTION_METHOD = "Amass Attack-Surface Discovery"

CATEGORY_SUBDOMAIN = "subdomain"
CATEGORY_DNS_ASSET = "dns_asset"
CATEGORY_HOST = "host"

DEFAULT_SEVERITY = "informational"
DEFAULT_CONFIDENCE = "high"

SUPPORTED_CATEGORIES = {
    CATEGORY_SUBDOMAIN,
    CATEGORY_DNS_ASSET,
    CATEGORY_HOST,
}


###############################################################################
# Normalization Helpers
###############################################################################


def _text(
    value: Any,
) -> str:
    """
    Normalize a value into stripped text.
    """

    if value is None:
        return ""

    return str(
        value
    ).strip()


def _optional_text(
    value: Any,
) -> str | None:
    """
    Normalize an optional textual value.
    """

    value = _text(
        value
    )

    return value or None


def _normalize_host(
    value: Any,
) -> str:
    """
    Normalize a hostname.

    The normalization intentionally remains conservative. It does not attempt
    DNS resolution and does not convert hostnames into IP addresses.
    """

    host = _text(
        value
    ).lower()

    if host.endswith(
        "."
    ):
        host = host[:-1]

    return host


def _normalize_category(
    value: Any,
) -> str:
    """
    Normalize an Amass finding category.
    """

    category = _text(
        value
    ).lower()

    aliases = {
        "subdomains": CATEGORY_SUBDOMAIN,
        "subdomain": CATEGORY_SUBDOMAIN,
        "dns": CATEGORY_DNS_ASSET,
        "dns_asset": CATEGORY_DNS_ASSET,
        "dns-asset": CATEGORY_DNS_ASSET,
        "host": CATEGORY_HOST,
        "hosts": CATEGORY_HOST,
        "asset": CATEGORY_DNS_ASSET,
    }

    return aliases.get(
        category,
        category,
    )


def _timestamp(
    value: Any,
) -> datetime:
    """
    Normalize an optional timestamp.

    Invalid or absent timestamps fall back to the current UTC time.
    """

    if isinstance(
        value,
        datetime,
    ):
        if value.tzinfo is None:
            return value.replace(
                tzinfo=timezone.utc
            )

        return value

    text = _text(
        value
    )

    if text:
        try:
            parsed = datetime.fromisoformat(
                text.replace(
                    "Z",
                    "+00:00",
                )
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed

        except ValueError:
            pass

    return datetime.now(
        timezone.utc
    )


def _unique_strings(
    values: Iterable[Any],
) -> list[str]:
    """
    Return unique normalized strings in stable input order.
    """

    result: list[str] = []

    for value in values:
        value = _text(
            value
        )

        if (
            value
            and value not in result
        ):
            result.append(
                value
            )

    return result


###############################################################################
# Collector
###############################################################################


class AmassCollector(CollectorBase):
    """
    Normalize Amass output into canonical ScopeForgeX Finding objects.

    Supported input forms include:

    - Amass JSON records
    - JSON Lines
    - a JSON list of records
    - mappings representing individual Amass records
    - plain-text hostname output
    - an iterable containing any of the above

    The collector does not execute Amass and does not perform DNS or network
    activity.
    """

    name = "amass"
    tool = "amass"

    description = (
        "Normalize Amass attack-surface discovery output into canonical "
        "ScopeForgeX findings."
    )

    source_tool = SOURCE_TOOL

    detection_method = DETECTION_METHOD

    ###########################################################################
    # Public API
    ###########################################################################



    @staticmethod
    def _finding_to_observation(
        finding: Any,
    ) -> CollectorObservation:
        """
        Convert a canonical Finding into a CollectorObservation.

        The native collector parser preserves the existing collector's
        normalized finding data while satisfying the universal collector
        observation contract.
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
        Parse an already-completed Amass execution result.

        Existing Amass normalization remains the source of truth; this
        canonical boundary only adapts its findings into observations.
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

        findings = self.collect_findings(
            output,
            target=target,
        )

        return [
            self._finding_to_observation(
                finding
            )
            for finding in findings
        ]

    def collect_findings(
        self,
        output: Any,
        *,
        target: str = "",
        timestamp: datetime | None = None,
    ) -> list[Finding]:
        """
        Collect findings from Amass output.

        Args:
            output:
                Raw Amass output or structured Amass records.

            target:
                Assessment target associated with the Amass execution.

            timestamp:
                Optional collection timestamp applied when individual records
                do not contain their own timestamp.

        Returns:
            A list of canonical Finding objects.

        Raises:
            TypeError:
                If the supplied output type is unsupported.
        """

        target = _text(
            target
        )

        collection_timestamp = (
            timestamp
            if timestamp is not None
            else datetime.now(
                timezone.utc
            )
        )

        records = self._parse_output(
            output
        )

        findings: list[Finding] = []

        for record in records:

            finding = self._record_to_finding(
                record,
                target=target,
                timestamp=collection_timestamp,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    def collect_json(
        self,
        output: str | bytes,
        *,
        target: str = "",
        timestamp: datetime | None = None,
    ) -> list[Finding]:
        """
        Collect findings from JSON or JSONL Amass output.
        """

        records = self._parse_json_output(
            output
        )

        findings: list[Finding] = []

        target = _text(
            target
        )

        collection_timestamp = (
            timestamp
            if timestamp is not None
            else datetime.now(
                timezone.utc
            )
        )

        for record in records:

            finding = self._record_to_finding(
                record,
                target=target,
                timestamp=collection_timestamp,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    def collect_text(
        self,
        output: str,
        *,
        target: str = "",
        timestamp: datetime | None = None,
    ) -> list[Finding]:
        """
        Collect findings from plain-text Amass output.

        Plain-text mode treats each non-empty line as a discovered hostname
        unless the line clearly contains structured information that can be
        parsed into a hostname.
        """

        if not isinstance(
            output,
            str,
        ):
            raise TypeError(
                "collect_text() expects a string."
            )

        target = _text(
            target
        )

        collection_timestamp = (
            timestamp
            if timestamp is not None
            else datetime.now(
                timezone.utc
            )
        )

        findings: list[Finding] = []

        for line in output.splitlines():

            record = self._text_line_to_record(
                line
            )

            if record is None:
                continue

            finding = self._record_to_finding(
                record,
                target=target,
                timestamp=collection_timestamp,
            )

            if finding is not None:
                findings.append(
                    finding
                )

        return findings

    ###########################################################################
    # Output Parsing
    ###########################################################################

    def _parse_output(
        self,
        output: Any,
    ) -> list[Mapping[str, Any]]:
        """
        Convert supported output forms into normalized record mappings.
        """

        if output is None:
            return []

        if isinstance(
            output,
            Mapping,
        ):
            return [
                output
            ]

        if isinstance(
            output,
            (bytes, bytearray),
        ):
            output = output.decode(
                "utf-8",
                errors="replace",
            )

        if isinstance(
            output,
            str,
        ):
            return self._parse_string_output(
                output
            )

        try:
            iterator = iter(
                output
            )
        except TypeError as exc:
            raise TypeError(
                "Amass collector input must be text, bytes, a mapping, "
                "or an iterable of records."
            ) from exc

        records: list[Mapping[str, Any]] = []

        for item in iterator:

            if isinstance(
                item,
                Mapping,
            ):
                records.append(
                    item
                )
                continue

            if isinstance(
                item,
                (bytes, bytearray),
            ):
                item = item.decode(
                    "utf-8",
                    errors="replace",
                )

            if isinstance(
                item,
                str,
            ):
                records.extend(
                    self._parse_string_output(
                        item
                    )
                )
                continue

            raise TypeError(
                "Amass iterable items must be mappings or text records."
            )

        return records

    def _parse_string_output(
        self,
        output: str,
    ) -> list[Mapping[str, Any]]:
        """
        Parse string output as JSON, JSONL or plain text.
        """

        text = output.strip()

        if not text:
            return []

        try:
            parsed = json.loads(
                text
            )

            return self._records_from_json_value(
                parsed
            )

        except json.JSONDecodeError:
            pass

        records: list[Mapping[str, Any]] = []

        jsonl_success = True

        for line in text.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            try:
                parsed = json.loads(
                    stripped
                )

            except json.JSONDecodeError:
                jsonl_success = False
                break

            records.extend(
                self._records_from_json_value(
                    parsed
                )
            )

        if jsonl_success and records:
            return records

        return self._parse_plain_text(
            text
        )

    @staticmethod
    def _parse_json_output(
        output: str | bytes,
    ) -> list[Mapping[str, Any]]:
        """
        Parse JSON/JSONL data without applying finding normalization.
        """

        if isinstance(
            output,
            bytes,
        ):
            output = output.decode(
                "utf-8",
                errors="replace",
            )

        if not isinstance(
            output,
            str,
        ):
            raise TypeError(
                "JSON output must be a string or bytes object."
            )

        text = output.strip()

        if not text:
            return []

        try:
            parsed = json.loads(
                text
            )

            return AmassCollector._records_from_json_value(
                parsed
            )

        except json.JSONDecodeError:
            pass

        records: list[Mapping[str, Any]] = []

        for line in text.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            parsed = json.loads(
                stripped
            )

            records.extend(
                AmassCollector._records_from_json_value(
                    parsed
                )
            )

        return records

    @staticmethod
    def _records_from_json_value(
        value: Any,
    ) -> list[Mapping[str, Any]]:
        """
        Convert a decoded JSON value into record mappings.
        """

        if isinstance(
            value,
            Mapping,
        ):
            return [
                value
            ]

        if isinstance(
            value,
            list,
        ):
            records: list[Mapping[str, Any]] = []

            for item in value:

                if isinstance(
                    item,
                    Mapping,
                ):
                    records.append(
                        item
                    )

            return records

        return []

    def _parse_plain_text(
        self,
        output: str,
    ) -> list[Mapping[str, Any]]:
        """
        Parse plain-text Amass output.
        """

        records: list[Mapping[str, Any]] = []

        for line in output.splitlines():

            record = self._text_line_to_record(
                line
            )

            if record is not None:
                records.append(
                    record
                )

        return records

    @staticmethod
    def _text_line_to_record(
        line: str,
    ) -> Mapping[str, Any] | None:
        """
        Convert one plain-text Amass line into a record.

        Amass text output commonly contains discovered hostnames. Empty lines,
        comments and obvious status messages are ignored.
        """

        line = line.strip()

        if not line:
            return None

        if line.startswith(
            "#"
        ):
            return None

        lowered = line.lower()

        ignored_prefixes = (
            "the enumeration",
            "enumeration",
            "starting",
            "finished",
            "collecting",
            "resolving",
            "attempting",
            "amass",
        )

        if lowered.startswith(
            ignored_prefixes
        ):
            return None

        # Some output modes may include whitespace-delimited metadata.
        # The first field is normally the discovered name.
        hostname = line.split(
            None,
            1,
        )[0].strip()

        if not hostname:
            return None

        return {
            "name": hostname,
        }

    ###########################################################################
    # Record Conversion
    ###########################################################################

    def _record_to_finding(
        self,
        record: Mapping[str, Any],
        *,
        target: str,
        timestamp: datetime,
    ) -> Finding | None:
        """
        Convert one Amass record into a canonical Finding.
        """

        if not isinstance(
            record,
            Mapping,
        ):
            return None

        host = self._extract_host(
            record
        )

        if not host:
            return None

        category = self._infer_category(
            record,
            host=host,
        )

        record_target = (
            _text(
                record.get(
                    "target"
                )
            )
            or target
        )

        source_timestamp = _timestamp(
            record.get(
                "timestamp"
            )
            or record.get(
                "time"
            )
            or record.get(
                "timestamp_utc"
            )
            or timestamp
        )

        record_metadata = self._metadata(
            record,
            host=host,
            category=category,
        )

        title = self._title(
            category,
            host,
        )

        description = self._description(
            category,
            host,
            record,
        )

        evidence = self._evidence(
            record,
        )

        finding_id = self._finding_id(
            category,
            host,
            record,
        )

        finding_data = {
            "title": title,
            "category": category,
            "severity": DEFAULT_SEVERITY,
            "confidence": DEFAULT_CONFIDENCE,
            "target": record_target,
            "host": host,
            "port": self._extract_port(
                record
            ),
            "url": _optional_text(
                record.get(
                    "url"
                )
            ),
            "parameter": None,
            "description": description,
            "evidence": evidence,
            "source_tool": SOURCE_TOOL,
            "detection_method": DETECTION_METHOD,
            "timestamp": source_timestamp,
            "cwe": None,
            "cve": self._extract_cve(
                record
            ),
            "references": self._references(
                record
            ),
            "impact": "",
            "remediation": "",
            "status": "open",
            "metadata": record_metadata,
        }

        return Finding.from_mapping(
            finding_data,
            finding_id=finding_id,
        )

    ###########################################################################
    # Record Field Extraction
    ###########################################################################

    @staticmethod
    def _extract_host(
        record: Mapping[str, Any],
    ) -> str:
        """
        Extract the strongest hostname/asset field from an Amass record.
        """

        candidates = (
            "name",
            "host",
            "hostname",
            "domain",
            "fqdn",
            "subdomain",
            "asset",
        )

        for field_name in candidates:

            value = _normalize_host(
                record.get(
                    field_name
                )
            )

            if value:
                return value

        return ""

    @classmethod
    def _extract_port(
        cls,
        record: Mapping[str, Any],
    ) -> int | None:
        """
        Extract an optional service port when supplied by Amass-derived data.
        """

        value = record.get(
            "port"
        )

        if value is None:
            return None

        try:
            port = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

        if 1 <= port <= 65535:
            return port

        return None

    @staticmethod
    def _extract_cve(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a CVE when present.

        Amass is not primarily a vulnerability scanner, so this field is
        normally absent. It is retained for compatibility with structured
        enrichment records.
        """

        value = _text(
            record.get(
                "cve"
            )
        )

        return value or None

    @staticmethod
    def _references(
        record: Mapping[str, Any],
    ) -> list[str]:
        """
        Extract references supplied by structured Amass data.
        """

        references = record.get(
            "references"
        )

        if references is None:
            references = record.get(
                "reference"
            )

        if references is None:
            return []

        if isinstance(
            references,
            str,
        ):
            return (
                [references.strip()]
                if references.strip()
                else []
            )

        if isinstance(
            references,
            Iterable,
        ):
            return _unique_strings(
                references
            )

        value = _text(
            references
        )

        return (
            [value]
            if value
            else []
        )

    ###########################################################################
    # Classification
    ###########################################################################

    @classmethod
    def _infer_category(
        cls,
        record: Mapping[str, Any],
        *,
        host: str,
    ) -> str:
        """
        Determine the most appropriate Amass finding category.
        """

        explicit = _normalize_category(
            record.get(
                "category"
            )
            or record.get(
                "type"
            )
            or record.get(
                "finding_type"
            )
        )

        if explicit in SUPPORTED_CATEGORIES:
            return explicit

        if cls._looks_like_dns_asset(
            record
        ):
            return CATEGORY_DNS_ASSET

        if cls._looks_like_subdomain(
            record,
            host=host,
        ):
            return CATEGORY_SUBDOMAIN

        return CATEGORY_HOST

    @staticmethod
    def _looks_like_subdomain(
        record: Mapping[str, Any],
        *,
        host: str,
    ) -> bool:
        """
        Determine whether a record represents a discovered subdomain.
        """

        explicit = _text(
            record.get(
                "subdomain"
            )
        )

        if explicit:
            return True

        record_type = _text(
            record.get(
                "type"
            )
        ).lower()

        if record_type in {
            "subdomain",
            "subdomains",
        }:
            return True

        return bool(
            host.count(
                "."
            ) >= 2
        )

    @staticmethod
    def _looks_like_dns_asset(
        record: Mapping[str, Any],
    ) -> bool:
        """
        Determine whether a structured record represents DNS asset data.
        """

        dns_fields = (
            "address",
            "addresses",
            "ip",
            "ips",
            "record",
            "record_type",
            "dns",
            "resolver",
        )

        return any(
            field_name in record
            for field_name in dns_fields
        )

    ###########################################################################
    # Finding Construction
    ###########################################################################

    @staticmethod
    def _title(
        category: str,
        host: str,
    ) -> str:
        """
        Build a deterministic finding title.
        """

        titles = {
            CATEGORY_SUBDOMAIN: "Discovered Subdomain",
            CATEGORY_DNS_ASSET: "Discovered DNS Asset",
            CATEGORY_HOST: "Discovered Host",
        }

        prefix = titles.get(
            category,
            "Discovered Asset",
        )

        return (
            f"{prefix}: {host}"
        )

    @staticmethod
    def _description(
        category: str,
        host: str,
        record: Mapping[str, Any],
    ) -> str:
        """
        Build a human-readable observation description.
        """

        if category == CATEGORY_SUBDOMAIN:
            description = (
                "Amass identified the host as part of the target's "
                f"attack surface: {host}."
            )

        elif category == CATEGORY_DNS_ASSET:
            description = (
                "Amass identified DNS-related asset information associated "
                f"with {host}."
            )

        else:
            description = (
                "Amass identified the host as an asset associated with the "
                f"assessment target: {host}."
            )

        relationship = _text(
            record.get(
                "relationship"
            )
        )

        if relationship:
            description += (
                f" Recorded relationship: {relationship}."
            )

        return description

    @staticmethod
    def _evidence(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve structured Amass record data as evidence.

        The original record is copied so subsequent caller mutation cannot
        alter the Finding evidence.
        """

        import copy

        return {
            "source": SOURCE_TOOL,
            "raw_record": copy.deepcopy(
                dict(
                    record
                )
            ),
        }

    @staticmethod
    def _metadata(
        record: Mapping[str, Any],
        *,
        host: str,
        category: str,
    ) -> dict[str, Any]:
        """
        Build structured Amass metadata.
        """

        import copy

        metadata: dict[str, Any] = {
            "collector": "amass",
            "asset": host,
            "asset_type": category,
        }

        relationship = _text(
            record.get(
                "relationship"
            )
        )

        if relationship:
            metadata[
                "relationship"
            ] = relationship

        source = _text(
            record.get(
                "source"
            )
        )

        if source:
            metadata[
                "amass_source"
            ] = source

        addresses = record.get(
            "addresses"
        )

        if addresses is not None:
            metadata[
                "addresses"
            ] = copy.deepcopy(
                addresses
            )

        asn = record.get(
            "asn"
        )

        if asn is not None:
            metadata[
                "asn"
            ] = copy.deepcopy(
                asn
            )

        cidr = record.get(
            "cidr"
        )

        if cidr is not None:
            metadata[
                "cidr"
            ] = copy.deepcopy(
                cidr
            )

        return metadata

    @staticmethod
    def _finding_id(
        category: str,
        host: str,
        record: Mapping[str, Any],
    ) -> str:
        """
        Generate a deterministic finding identifier.

        An explicit Amass ID is preferred. Otherwise a stable SHA-256-derived
        identifier is generated from the category and normalized host.
        """

        import hashlib

        explicit = _text(
            record.get(
                "id"
            )
        )

        if explicit:
            return (
                f"SF-AMASS-{explicit}"
            )

        seed = (
            f"{category}|"
            f"{_normalize_host(host)}"
        )

        digest = hashlib.sha256(
            seed.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

        return (
            f"SF-AMASS-{digest}"
        )


###############################################################################
# Convenience API
###############################################################################


def collect_amass_findings(
    output: Any,
    *,
    target: str = "",
    timestamp: datetime | None = None,
) -> list[Finding]:
    """
    Convenience function for collecting Amass findings.

    Example
    -------

        findings = collect_amass_findings(
            amass_output,
            target="example.com",
        )
    """

    collector = AmassCollector()

    return collector.collect_findings(
        output,
        target=target,
        timestamp=timestamp,
    )


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "SOURCE_TOOL",
    "DETECTION_METHOD",
    "CATEGORY_SUBDOMAIN",
    "CATEGORY_DNS_ASSET",
    "CATEGORY_HOST",
    "SUPPORTED_CATEGORIES",
    "AmassCollector",
    "collect_amass_findings",
]
