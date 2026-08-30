"""
ScopeForgeX Nuclei Collector
=============================

Parses Nuclei scanner output into structured ScopeForgeX observations.

Nuclei is the primary broad vulnerability assessment engine in ScopeForgeX.
The collector converts Nuclei's structured or line-oriented output into
normalized observations while preserving the original scanner evidence.

Primary observations:

    VULNERABILITY
    MISCONFIGURATION
    EXPOSED_RESOURCE
    CVE
    SECURITY_ISSUE

Architecture
------------

Nuclei
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
NucleiCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes Nuclei.
- The collector never constructs Nuclei commands.
- Raw Nuclei output remains preserved in the ExecutionResult artifacts.
- JSONL output is treated as the primary structured format.
- Plain-text Nuclei output is also supported.
- Duplicate observations are removed deterministically.
- Severity is preserved when supplied by Nuclei.
- Confidence is derived from the Nuclei result but is not treated as
  manual confirmation.
- CVE identifiers are preserved as structured metadata when available.
- CWE identifiers are preserved when available.
- References and matched evidence are retained.
- Collection failures do not destroy the original execution result.
- The collector does not perform network requests.

v1.0.0
"""

from __future__ import annotations

import json
import re
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


TOOL_NAME = "nuclei"

OBSERVATION_VULNERABILITY = "VULNERABILITY"
OBSERVATION_MISCONFIGURATION = "MISCONFIGURATION"
OBSERVATION_EXPOSED_RESOURCE = "EXPOSED_RESOURCE"
OBSERVATION_CVE = "CVE"
OBSERVATION_SECURITY_ISSUE = "SECURITY_ISSUE"


###############################################################################
# Normalization Constants
###############################################################################


_CVE_PATTERN = re.compile(
    r"\bCVE-\d{4}-\d{4,}\b",
    re.IGNORECASE,
)

_CWE_PATTERN = re.compile(
    r"\bCWE-\d+\b",
    re.IGNORECASE,
)

_SEVERITY_ALIASES = {
    "info": "informational",
    "information": "informational",
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "critical": "critical",
    "unknown": "informational",
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


class NucleiCollector(CollectorBase):
    """
    Collect structured vulnerability observations from Nuclei output.

    Nuclei normally emits JSONL records when the JSON output mode is enabled.
    The collector also accepts plain-text output so that ScopeForgeX remains
    compatible with executions that did not request structured output.
    """

    name = "nuclei"
    tool = "nuclei"

    description = (
        "Parses Nuclei vulnerability and misconfiguration results into "
        "structured ScopeForgeX observations."
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
        Parse Nuclei output into structured observations.

        Artifact content is preferred when available because artifacts are
        persistent evidence associated with the execution. Stdout is also
        inspected so executions without a dedicated output artifact remain
        collectable.
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

        seen: set[tuple[str, str, str]] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed = self._parse_record(
                    record
                )

                if parsed is None:
                    continue

                normalized = self._normalize_record(
                    parsed
                )

                if normalized is None:
                    continue

                url = normalized.get(
                    "url"
                ) or ""

                template_id = normalized.get(
                    "template_id"
                ) or ""

                title = normalized.get(
                    "title"
                ) or ""

                key = (
                    str(
                        url
                    ),
                    str(
                        template_id
                    ),
                    str(
                        title
                    ).lower(),
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                observations.extend(
                    self._build_observations(
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
        Return available Nuclei evidence as labelled text.

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
        Convert raw Nuclei content into logical records.

        JSON objects are parsed individually. Non-JSON lines are retained as
        plain-text records for compatibility with standard Nuclei output.
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
        Normalize one raw Nuclei record into a parser-friendly structure.
        """

        if isinstance(
            record,
            Mapping,
        ):
            return dict(
                record
            )

        return self._parse_text_record(
            record
        )

    @staticmethod
    def _parse_text_record(
        record: str,
    ) -> dict[str, Any] | None:
        """
        Parse common Nuclei plain-text output.

        Typical output resembles:

            [template-id] [protocol] [severity] [url]

        The parser intentionally remains conservative and does not attempt to
        reconstruct fields that cannot be identified reliably.
        """

        value = str(
            record
        ).strip()

        if not value:
            return None

        severity = None

        severity_match = re.search(
            r"\[(critical|high|medium|low|info|informational)\]",
            value,
            re.IGNORECASE,
        )

        if severity_match:
            severity = severity_match.group(
                1
            )

        urls = re.findall(
            r"https?://[^\s\]]+",
            value,
            re.IGNORECASE,
        )

        url = (
            urls[0]
            if urls
            else None
        )

        template_id = None

        template_match = re.search(
            r"^\[([^\]]+)\]",
            value,
        )

        if template_match:
            template_id = template_match.group(
                1
            )

        cves = [
            match.upper()
            for match in _CVE_PATTERN.findall(
                value
            )
        ]

        cwes = [
            match.upper()
            for match in _CWE_PATTERN.findall(
                value
            )
        ]

        if (
            not url
            and not cves
            and not template_id
        ):
            return None

        return {
            "template-id": template_id,
            "info": {
                "name": template_id or "Nuclei Finding",
                "severity": severity or "info",
            },
            "matched-at": url,
            "host": (
                url
                if url
                else None
            ),
            "cve": cves,
            "cwe": cwes,
            "matcher-name": None,
            "extracted-results": [],
            "raw": value,
        }

    ###########################################################################
    # Structured Record Normalization
    ###########################################################################

    def _normalize_record(
        self,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """
        Normalize a Nuclei JSON record.

        Nuclei has emitted slightly different field combinations across
        versions and output modes, so this method accepts common aliases.
        """

        info = record.get(
            "info",
            {},
        )

        if not isinstance(
            info,
            Mapping,
        ):
            info = {}

        template_id = self._first_text(
            record,
            (
                "template-id",
                "template_id",
                "template",
                "templateID",
            ),
        )

        name = self._first_text(
            info,
            (
                "name",
                "title",
            ),
        )

        if not name:
            name = self._first_text(
                record,
                (
                    "name",
                    "title",
                ),
            )

        severity = self._normalize_severity(
            self._first_text(
                info,
                (
                    "severity",
                ),
            )
            or self._first_text(
                record,
                (
                    "severity",
                ),
            )
        )

        url = self._first_text(
            record,
            (
                "matched-at",
                "matched_at",
                "url",
                "host",
                "endpoint",
            ),
        )

        host = self._first_text(
            record,
            (
                "host",
            ),
        )

        if not host and url:
            host = self._extract_host(
                url
            )

        matcher_name = self._first_text(
            record,
            (
                "matcher-name",
                "matcher_name",
            ),
        )

        extracted_results = self._normalize_list(
            record.get(
                "extracted-results",
                record.get(
                    "extracted_results",
                    [],
                ),
            )
        )

        cves = self._extract_identifiers(
            record,
            info,
            _CVE_PATTERN,
            (
                "cve",
                "cves",
            ),
        )

        cwes = self._extract_identifiers(
            record,
            info,
            _CWE_PATTERN,
            (
                "cwe",
                "cwes",
            ),
        )

        references = self._normalize_references(
            info.get(
                "reference",
                info.get(
                    "references",
                    record.get(
                        "reference",
                        record.get(
                            "references",
                            [],
                        ),
                    ),
                ),
            )
        )

        classification = info.get(
            "classification",
            {},
        )

        if isinstance(
            classification,
            Mapping,
        ):
            cves.extend(
                self._extract_identifiers_from_value(
                    classification.get(
                        "cve"
                    ),
                    _CVE_PATTERN,
                )
            )

            cwes.extend(
                self._extract_identifiers_from_value(
                    classification.get(
                        "cwe-id",
                        classification.get(
                            "cwe"
                        ),
                    ),
                    _CWE_PATTERN,
                )
            )

        cves = self._unique_strings(
            cves
        )

        cwes = self._unique_strings(
            cwes
        )

        raw_evidence = self._evidence_from_record(
            record
        )

        if (
            not name
            and not url
            and not template_id
            and not cves
            and not cwes
        ):
            return None

        return {
            "template_id": template_id,
            "title": (
                name
                or template_id
                or "Nuclei Security Finding"
            ),
            "severity": severity,
            "url": url,
            "host": host,
            "matcher_name": matcher_name,
            "extracted_results": extracted_results,
            "cves": cves,
            "cwes": cwes,
            "references": references,
            "description": self._first_text(
                info,
                (
                    "description",
                ),
            ),
            "impact": self._first_text(
                info,
                (
                    "impact",
                ),
            ),
            "remediation": self._first_text(
                info,
                (
                    "remediation",
                    "remediation-code",
                ),
            ),
            "type": self._classify_record(
                record,
                info,
            ),
            "evidence": raw_evidence,
            "raw_record": dict(
                record
            ),
        }

    ###########################################################################
    # Observation Construction
    ###########################################################################

    def _build_observations(
        self,
        record: Mapping[str, Any],
        *,
        target: str | None,
        source: str,
    ) -> list[CollectorObservation]:
        """
        Build the primary and identifier observations for one Nuclei result.
        """

        observations: list[CollectorObservation] = []

        observation_type = self._primary_observation_type(
            record
        )

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
            "template_id": record.get(
                "template_id"
            ),
            "matcher_name": record.get(
                "matcher_name"
            ),
            "severity": severity,
            "cves": list(
                record.get(
                    "cves",
                    [],
                )
            ),
            "cwes": list(
                record.get(
                    "cwes",
                    [],
                )
            ),
            "references": list(
                record.get(
                    "references",
                    [],
                )
            ),
            "extracted_results": list(
                record.get(
                    "extracted_results",
                    [],
                )
            ),
            "nuclei_type": record.get(
                "type"
            ),
        }

        primary = CollectorObservation(
            observation_type=observation_type,
            value=(
                url
                or record.get(
                    "title"
                )
                or record.get(
                    "template_id"
                )
                or "Nuclei finding"
            ),
            target=target,
            host=host,
            port=port,
            url=url,
            description=self._optional_text(
                record.get(
                    "description"
                )
            ),
            evidence=record.get(
                "evidence"
            ),
            source_tool=TOOL_NAME,
            detection_method=(
                "Nuclei template detection"
            ),
            confidence=confidence,
            metadata=metadata,
        )

        observations.append(
            primary
        )

        for cve in record.get(
            "cves",
            [],
        ):
            observations.append(
                CollectorObservation(
                    observation_type=OBSERVATION_CVE,
                    value=cve,
                    target=target,
                    host=host,
                    port=port,
                    url=url,
                    evidence=record.get(
                        "evidence"
                    ),
                    source_tool=TOOL_NAME,
                    detection_method=(
                        "Nuclei CVE classification"
                    ),
                    confidence=confidence,
                    metadata={
                        "template_id": record.get(
                            "template_id"
                        ),
                        "severity": severity,
                    },
                )
            )

        return observations

    ###########################################################################
    # Classification
    ###########################################################################

    @staticmethod
    def _classify_record(
        record: Mapping[str, Any],
        info: Mapping[str, Any],
    ) -> str:
        """
        Determine the broad Nuclei result class.
        """

        record_type = str(
            record.get(
                "type",
                ""
            )
        ).strip().lower()

        tags = NucleiCollector._normalize_list(
            info.get(
                "tags",
                [],
            )
        )

        text = " ".join(
            [
                record_type,
                " ".join(
                    tags
                ),
                str(
                    info.get(
                        "name",
                        "",
                    )
                ),
            ]
        ).lower()

        if (
            "misconfig" in text
            or "misconfiguration" in text
        ):
            return "misconfiguration"

        if (
            "exposure" in text
            or "exposed" in text
            or "disclosure" in text
        ):
            return "exposed_resource"

        if (
            "vulnerability" in text
            or "cve" in text
        ):
            return "vulnerability"

        return (
            record_type
            or "security_issue"
        )

    @staticmethod
    def _primary_observation_type(
        record: Mapping[str, Any],
    ) -> str:
        """
        Map a normalized Nuclei result to its primary observation type.
        """

        result_type = str(
            record.get(
                "type",
                "",
            )
        ).strip().lower()

        if result_type == "misconfiguration":
            return OBSERVATION_MISCONFIGURATION

        if result_type == "exposed_resource":
            return OBSERVATION_EXPOSED_RESOURCE

        if result_type == "vulnerability":
            return OBSERVATION_VULNERABILITY

        if record.get(
            "cves"
        ):
            return OBSERVATION_VULNERABILITY

        return OBSERVATION_SECURITY_ISSUE

    ###########################################################################
    # Identifier Helpers
    ###########################################################################

    @staticmethod
    def _extract_identifiers(
        record: Mapping[str, Any],
        info: Mapping[str, Any],
        pattern: re.Pattern[str],
        keys: Iterable[str],
    ) -> list[str]:
        """
        Extract identifiers from common Nuclei fields.
        """

        values: list[Any] = []

        for key in keys:
            if key in record:
                values.append(
                    record.get(
                        key
                    )
                )

            if key in info:
                values.append(
                    info.get(
                        key
                    )
                )

        result: list[str] = []

        for value in values:
            result.extend(
                NucleiCollector._extract_identifiers_from_value(
                    value,
                    pattern,
                )
            )

        return NucleiCollector._unique_strings(
            result
        )

    @staticmethod
    def _extract_identifiers_from_value(
        value: Any,
        pattern: re.Pattern[str],
    ) -> list[str]:
        """
        Extract identifiers from scalar or collection values.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):
            matches = pattern.findall(
                value
            )

            return [
                match.upper()
                for match in matches
            ]

        if isinstance(
            value,
            Iterable,
        ) and not isinstance(
            value,
            Mapping,
        ):
            result: list[str] = []

            for item in value:
                result.extend(
                    NucleiCollector._extract_identifiers_from_value(
                        item,
                        pattern,
                    )
                )

            return result

        return NucleiCollector._extract_identifiers_from_value(
            str(
                value
            ),
            pattern,
        )

    ###########################################################################
    # Evidence / Reference Helpers
    ###########################################################################

    @staticmethod
    def _evidence_from_record(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve useful Nuclei evidence fields without discarding the
        original structured record.
        """

        evidence: dict[str, Any] = {
            "raw_record": dict(
                record
            ),
        }

        for key in (
            "matched-at",
            "matched_at",
            "host",
            "type",
            "template-id",
            "template_id",
            "matcher-name",
            "matcher_name",
            "extracted-results",
            "extracted_results",
            "ip",
            "timestamp",
        ):
            if key in record:
                evidence[key] = record.get(
                    key
                )

        return evidence

    @staticmethod
    def _normalize_references(
        value: Any,
    ) -> list[str]:
        """
        Normalize Nuclei references into a unique ordered list.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):
            return (
                [value.strip()]
                if value.strip()
                else []
            )

        if isinstance(
            value,
            Mapping,
        ):
            return [
                str(
                    item
                ).strip()
                for item in value.values()
                if str(
                    item
                ).strip()
            ]

        if isinstance(
            value,
            Iterable,
        ):
            return NucleiCollector._unique_strings(
                [
                    str(
                        item
                    ).strip()
                    for item in value
                    if str(
                        item
                    ).strip()
                ]
            )

        value = str(
            value
        ).strip()

        return (
            [value]
            if value
            else []
        )

    ###########################################################################
    # General Normalization Helpers
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
                value = value.strip()

                if value:
                    return value

            elif value:
                return str(
                    value
                ).strip()

        return None

    @staticmethod
    def _normalize_list(
        value: Any,
    ) -> list[Any]:
        """
        Normalize a value into a list without splitting scalar strings.
        """

        if value is None:
            return []

        if isinstance(
            value,
            list,
        ):
            return list(
                value
            )

        if isinstance(
            value,
            tuple,
        ):
            return list(
                value
            )

        if isinstance(
            value,
            set,
        ):
            return list(
                value
            )

        return [
            value
        ]

    @staticmethod
    def _unique_strings(
        values: Iterable[Any],
    ) -> list[str]:
        """
        Return unique non-empty strings while preserving input order.
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

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """
        Normalize a Nuclei severity value.

        Unknown or missing values become informational rather than introducing
        a non-canonical severity into ScopeForgeX.
        """

        normalized = (
            str(
                value
            ).strip().lower()
            if value is not None
            else ""
        )

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

        normalized = str(
            value
        ).strip()

        return normalized or None

    ###########################################################################
    # Target / URL Helpers
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
        value: str,
    ) -> str | None:
        """
        Extract a hostname from a URL or host-like value.
        """

        try:
            parsed = urlparse(
                value
            )

        except ValueError:
            return None

        if parsed.hostname:
            return parsed.hostname

        return (
            value
            if value
            else None
        )

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


###############################################################################
# Public API
###############################################################################


__all__ = [
    "NucleiCollector",
]
