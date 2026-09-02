"""
ScopeForgeX Nuclei Collector
============================

Collector for parsing Nuclei scanner output into structured ScopeForgeX
observations.

The collector converts Nuclei structured JSON/JSONL and supported plain-text
finding output into ``CollectorObservation`` objects while preserving the
original scanner evidence.

Responsibilities
----------------

- Parse Nuclei execution results.
- Parse Nuclei JSON/JSONL output.
- Parse genuine Nuclei plain-text finding lines.
- Ignore Nuclei operational/status messages.
- Normalize severity, host and URL information.
- Preserve CVE/CWE identifiers and references.
- Preserve raw scanner evidence.
- Produce observations for the universal ScopeForgeX finding pipeline.

The collector does not:

- Execute Nuclei.
- Construct Nuclei commands.
- Perform network requests.
- Perform final risk classification.
- Perform finding correlation.
- Perform finding deduplication.

Important distinction
---------------------

Nuclei writes both security results and operational diagnostics.

For example:

    [INF] Current nuclei version: ...
    [INF] Skipped example.com:80 ...
    [INF] Scan completed in ...

These are execution diagnostics, not findings.

Only genuine security-result records are allowed across the collector boundary.

v1.4.0
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

_ANSI_PATTERN = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
)

_SEVERITY_PATTERN = re.compile(
    r"\[(critical|high|medium|moderate|low|info|informational)\]",
    re.IGNORECASE,
)

_OPERATIONAL_LEVELS = {
    "INF",
    "WRN",
    "WARN",
    "ERR",
    "ERROR",
    "DBG",
    "DEBU",
    "TRAC",
    "TRACE",
}

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

_OPERATIONAL_MARKERS = (
    "current nuclei version:",
    "current nuclei-templates version:",
    "new templates added",
    "templates loaded for current scan:",
    "executing ",
    "targets loaded for current scan:",
    "running httpx on input host",
    "found 0 url from httpx",
    "templates clustered:",
    "skipped ",
    "scan completed in ",
    "no results found",
)


###############################################################################
# Collector
###############################################################################


class NucleiCollector(CollectorBase):
    """
    Collect structured vulnerability observations from Nuclei output.

    Nuclei normally emits JSONL records when JSON output is enabled. The
    collector also accepts plain-text Nuclei finding output when structured
    output is unavailable.
    """

    name = "nuclei"

    tool = "nuclei"

    description = (
        "Parse Nuclei vulnerability, misconfiguration and exposure results "
        "into structured ScopeForgeX observations."
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

        Both stdout and execution artifacts are inspected.

        Artifact content may contain the persistent Nuclei log/output produced
        by ScopeForgeX. Duplicate source paths are processed only once.
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

                normalized = self._normalize_record(
                    parsed
                )

                if normalized is None:
                    continue

                url = (
                    normalized.get(
                        "url"
                    )
                    or ""
                )

                template_id = (
                    normalized.get(
                        "template_id"
                    )
                    or ""
                )

                title = (
                    normalized.get(
                        "title"
                    )
                    or ""
                )

                key = (
                    str(url),
                    str(template_id),
                    str(title).lower(),
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
    ) -> list[
        tuple[str, str]
    ]:
        """
        Return available Nuclei evidence as labelled text.

        Stdout is always considered when non-empty.

        Artifact paths may come from the explicit collector context or the
        ExecutionResult itself.
        """

        contents: list[
            tuple[str, str]
        ] = []

        seen_paths: set[str] = set()

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

        artifact_values: list[Any] = []

        context_artifacts = ctx.get(
            "artifacts",
            [],
        )

        if isinstance(
            context_artifacts,
            Iterable,
        ) and not isinstance(
            context_artifacts,
            (str, bytes, Mapping),
        ):
            artifact_values.extend(
                context_artifacts
            )

        execution_artifacts = getattr(
            execution_result,
            "artifacts",
            [],
        )

        if isinstance(
            execution_artifacts,
            Iterable,
        ) and not isinstance(
            execution_artifacts,
            (str, bytes, Mapping),
        ):
            artifact_values.extend(
                execution_artifacts
            )

        for artifact in artifact_values:

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

            try:
                content = read_text_file(
                    path
                )
            except Exception:
                continue

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
        Resolve an artifact representation into a filesystem path.
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

        if isinstance(
            value,
            Mapping,
        ):
            value = (
                value.get("path")
                or value.get("file")
                or value.get("location")
            )

        if value is None:
            return None

        path = Path(
            str(value)
        )

        if not path.exists():
            return None

        return path

    ###########################################################################
    # Record Iteration
    ###########################################################################

    @staticmethod
    def _iter_records(
        content: str,
    ) -> list[
        str | dict[str, Any]
    ]:
        """
        Convert raw Nuclei content into logical records.

        JSON objects are parsed individually. Non-JSON lines are retained so
        genuine plain-text findings can be parsed separately.
        """

        records: list[
            str | dict[str, Any]
        ] = []

        for line in str(
            content
        ).splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            if (
                stripped.startswith("{")
                and stripped.endswith("}")
            ):
                try:
                    decoded = json.loads(
                        stripped
                    )
                except json.JSONDecodeError:
                    decoded = None

                if isinstance(
                    decoded,
                    dict,
                ):
                    records.append(
                        decoded
                    )
                    continue

            records.append(
                stripped
            )

        return records

    @staticmethod
    def _parse_record(
        record: str | dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Parse one record into a mapping.
        """

        if isinstance(
            record,
            Mapping,
        ):
            return dict(
                record
            )

        return NucleiCollector._parse_text_record(
            str(record)
        )

    ###########################################################################
    # Plain-Text Parsing
    ###########################################################################

    @staticmethod
    def _strip_ansi(
        value: Any,
    ) -> str:
        """
        Remove terminal control sequences.
        """

        return _ANSI_PATTERN.sub(
            "",
            str(
                value
                if value is not None
                else ""
            ),
        )

    @classmethod
    def _is_operational_line(
        cls,
        value: str,
    ) -> bool:
        """
        Determine whether a line is an Nuclei operational/diagnostic message.

        Operational messages are never promoted to findings.
        """

        clean = cls._strip_ansi(
            value
        ).strip()

        if not clean:
            return True

        level_match = re.match(
            r"^\[\s*([A-Za-z]+)\s*\]",
            clean,
        )

        if level_match:
            level = (
                level_match.group(1)
                .strip()
                .upper()
            )

            if level in _OPERATIONAL_LEVELS:
                return True

        lowered = clean.lower()

        return lowered.startswith(
            _OPERATIONAL_MARKERS
        )

    @classmethod
    def _parse_text_record(
        cls,
        record: str,
    ) -> dict[str, Any] | None:
        """
        Parse a genuine Nuclei plain-text result.

        Common finding format:

            [medium] template-id [http] [https://example.com/path]

        Nuclei diagnostics such as ``[INF] Skipped ...`` are rejected before
        any URL/template extraction occurs.
        """

        value = cls._strip_ansi(
            record
        ).strip()

        if not value:
            return None

        if cls._is_operational_line(
            value
        ):
            return None

        severity_match = _SEVERITY_PATTERN.search(
            value
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

        # Real plain-text findings should expose a recognized severity or
        # an explicit CVE. This prevents arbitrary URLs/status lines from
        # becoming SECURITY_ISSUE findings.
        if (
            severity_match is None
            and not cves
        ):
            return None

        severity = (
            severity_match.group(
                1
            )
            if severity_match is not None
            else "informational"
        )

        # Extract URLs while excluding surrounding punctuation and markup.
        urls = re.findall(
            r'https?://[^\s\]\)\}"\'<>]+',
            value,
            re.IGNORECASE,
        )

        url = None

        if urls:
            url = urls[0].rstrip(
                "\"'.,:;"
            )

        remainder = value

        if severity_match is not None:
            remainder = value[
                severity_match.end():
            ].strip()

        # The token immediately after the severity is normally the template
        # identifier/name.
        template_match = re.match(
            r"([^\s\[\]]+)",
            remainder,
        )

        template_id = (
            template_match.group(
                1
            ).strip()
            if template_match is not None
            else None
        )

        if template_id:
            template_id = template_id.rstrip(
                "\"'.,:;"
            )

        if not (
            template_id
            or url
            or cves
        ):
            return None

        title = (
            template_id
            or (
                cves[0]
                if cves
                else "Nuclei Security Finding"
            )
        )

        return {
            "template-id": template_id,
            "info": {
                "name": title,
                "severity": severity,
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
        Normalize a Nuclei structured record.

        Operational records embedded in structured output are rejected when
        they identify an operational log level rather than a security result.
        """

        if not isinstance(
            record,
            Mapping,
        ):
            return None

        info = record.get(
            "info",
            {},
        )

        if not isinstance(
            info,
            Mapping,
        ):
            info = {}

        raw_value = self._first_text(
            record,
            (
                "raw",
                "raw_output",
                "message",
            ),
        )

        clean_raw = self._strip_ansi(
            raw_value
        ).strip()

        if (
            clean_raw
            and self._is_operational_line(
                clean_raw
            )
        ):
            return None

        template_id = self._first_text(
            record,
            (
                "template-id",
                "template_id",
                "template",
                "templateID",
            ),
        )

        template_id = self._strip_ansi(
            template_id
        ).strip()

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

        name = self._strip_ansi(
            name
        ).strip()

        if (
            template_id.upper()
            in _OPERATIONAL_LEVELS
            and not _CVE_PATTERN.search(
                clean_raw
            )
        ):
            return None

        if (
            name.upper()
            in _OPERATIONAL_LEVELS
            and not _CVE_PATTERN.search(
                clean_raw
            )
        ):
            return None

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
                "endpoint",
            ),
        )

        url = self._normalize_url(
            url
        )

        host = self._first_text(
            record,
            (
                "host",
            ),
        )

        host = self._normalize_host(
            host
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

        record_type = self._classify_record(
            record,
            info,
        )

        if not (
            name
            or url
            or template_id
            or cves
            or cwes
        ):
            return None

        # A structured informational record without any security semantics
        # should not be promoted automatically.
        if (
            severity == "informational"
            and not cves
            and not self._structured_security_signal(
                record,
                info,
            )
        ):
            return None

        description = self._first_text(
            info,
            (
                "description",
            ),
        )

        impact = self._first_text(
            info,
            (
                "impact",
            ),
        )

        remediation = self._first_text(
            info,
            (
                "remediation",
                "remediation-code",
            ),
        )

        evidence = self._evidence_from_record(
            record
        )

        return {
            "template_id": (
                template_id
                or None
            ),
            "title": (
                name
                or template_id
                or "Nuclei Security Finding"
            ),
            "severity": severity,
            "url": url,
            "host": host,
            "matcher_name": (
                matcher_name
                or None
            ),
            "extracted_results": extracted_results,
            "cves": cves,
            "cwes": cwes,
            "references": references,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "type": record_type,
            "evidence": evidence,
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
        Build normalized Nuclei observations.
        """

        observations: list[
            CollectorObservation
        ] = []

        observation_type = (
            self._primary_observation_type(
                record
            )
        )

        url = self._normalize_url(
            record.get(
                "url"
            )
        )

        host = self._normalize_host(
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

        title = self._optional_text(
            record.get(
                "title"
            )
        ) or "Nuclei Security Finding"

        primary = CollectorObservation(
            observation_type=observation_type,
            value=(
                url
                or title
                or record.get(
                    "template_id"
                )
                or "Nuclei Security Finding"
            ),
            title=title,
            target=target,
            host=host,
            port=port,
            url=url,
            description=self._optional_text(
                record.get(
                    "description"
                )
            ),
            impact=self._optional_text(
                record.get(
                    "impact"
                )
            ),
            remediation=self._optional_text(
                record.get(
                    "remediation"
                )
            ),
            severity=severity.title(),
            confidence=confidence,
            status="Pending",
            evidence=record.get(
                "evidence"
            ),
            source_tool=TOOL_NAME,
            detection_method=(
                "Nuclei template detection"
            ),
            cwe=(
                record.get(
                    "cwes",
                    [None],
                )[0]
                if record.get(
                    "cwes",
                    [],
                )
                else None
            ),
            cve=(
                record.get(
                    "cves",
                    [None],
                )[0]
                if record.get(
                    "cves",
                    [],
                )
                else None
            ),
            references=list(
                record.get(
                    "references",
                    [],
                )
                or []
            ),
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
                    title=str(
                        cve
                    ),
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
                    status="Pending",
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
                "",
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
                " ".join(tags),
                str(
                    info.get(
                        "name",
                        "",
                    )
                ),
                str(
                    info.get(
                        "description",
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
        Map a normalized Nuclei record to a primary observation type.
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

    @staticmethod
    def _structured_security_signal(
        record: Mapping[str, Any],
        info: Mapping[str, Any],
    ) -> bool:
        """
        Determine whether an informational structured result has explicit
        security semantics and is therefore worth retaining.
        """

        meaningful_fields = (
            "matched-at",
            "matched_at",
            "matcher-name",
            "matcher_name",
            "extracted-results",
            "extracted_results",
            "type",
        )

        if any(
            field in record
            and record.get(field) not in (
                None,
                "",
                [],
            )
            for field in meaningful_fields
        ):
            return True

        tags = NucleiCollector._normalize_list(
            info.get(
                "tags",
                [],
            )
        )

        return any(
            token in {
                "misconfig",
                "misconfiguration",
                "exposure",
                "exposed",
                "disclosure",
                "vulnerability",
                "cve",
                "security",
            }
            for token in (
                str(tag).lower()
                for tag in tags
            )
        )

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
        Extract identifiers from scalar or iterable values.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):
            return [
                match.upper()
                for match in pattern.findall(
                    value
                )
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
    # Evidence / References
    ###########################################################################

    @staticmethod
    def _evidence_from_record(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve structured Nuclei evidence.
        """

        import copy

        evidence: dict[str, Any] = {
            "raw_record": copy.deepcopy(
                dict(
                    record
                )
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
                evidence[key] = copy.deepcopy(
                    record.get(
                        key
                    )
                )

        return evidence

    @staticmethod
    def _normalize_references(
        value: Any,
    ) -> list[str]:
        """
        Normalize Nuclei references into unique ordered strings.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):
            cleaned = (
                value.strip()
            )

            return (
                [cleaned]
                if cleaned
                else []
            )

        if isinstance(
            value,
            Mapping,
        ):
            return NucleiCollector._unique_strings(
                [
                    str(item).strip()
                    for item in value.values()
                    if str(item).strip()
                ]
            )

        if isinstance(
            value,
            Iterable,
        ):
            return NucleiCollector._unique_strings(
                [
                    str(item).strip()
                    for item in value
                    if str(item).strip()
                ]
            )

        cleaned = str(
            value
        ).strip()

        return (
            [cleaned]
            if cleaned
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
        Return the first non-empty textual field.
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
                cleaned = value.strip()

                if cleaned:
                    return cleaned

            elif value:
                return str(
                    value
                ).strip()

        return None

    @staticmethod
    def _optional_text(
        value: Any,
    ) -> str | None:
        """
        Normalize an optional textual value.
        """

        if value is None:
            return None

        cleaned = str(
            value
        ).strip()

        return (
            cleaned
            if cleaned
            else None
        )

    @staticmethod
    def _normalize_list(
        value: Any,
    ) -> list[Any]:
        """
        Normalize a scalar or iterable into a list.
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

        if isinstance(
            value,
            str,
        ):
            cleaned = value.strip()

            return (
                [cleaned]
                if cleaned
                else []
            )

        return [
            value
        ]

    @staticmethod
    def _unique_strings(
        values: Iterable[Any],
    ) -> list[str]:
        """
        Return unique non-empty strings in stable order.
        """

        result: list[str] = []
        seen: set[str] = set()

        for value in values:

            cleaned = str(
                value
            ).strip()

            if not cleaned:
                continue

            if cleaned in seen:
                continue

            seen.add(
                cleaned
            )

            result.append(
                cleaned
            )

        return result

    @staticmethod
    def _normalize_severity(
        value: Any,
    ) -> str:
        """
        Normalize a Nuclei severity value.
        """

        normalized = str(
            value
            if value is not None
            else "informational"
        ).strip().lower()

        return _SEVERITY_ALIASES.get(
            normalized,
            "informational",
        )

    @classmethod
    def _normalize_url(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize a URL into a clean HTTP(S) URL.

        Markdown links, terminal formatting and surrounding punctuation are
        stripped from parser input before the URL is retained.
        """

        if value is None:
            return None

        text = cls._strip_ansi(
            value
        ).strip()

        if not text:
            return None

        # Convert Markdown link syntax:
        #
        # [https://example.com](https://example.com)
        #
        markdown_match = re.fullmatch(
            r"\[([^\]]+)\]\((https?://[^)]+)\)",
            text,
            re.IGNORECASE,
        )

        if markdown_match:
            text = markdown_match.group(
                2
            ).strip()

        # If surrounding text contains a URL, prefer the actual URL token.
        url_match = re.search(
            r"https?://[^\s\]\)\}" "'<>]+",
            text,
            re.IGNORECASE,
        )

        if url_match:
            text = url_match.group(
                0
            )

        text = text.strip(
            "\"'`"
        ).rstrip(
            "\"'.,:;"
        )

        try:
            parsed = urlparse(
                text
            )
        except ValueError:
            return None

        if parsed.scheme.lower() not in {
            "http",
            "https",
        }:
            return None

        if not parsed.hostname:
            return None

        return text

    @staticmethod
    def _normalize_host(
        value: Any,
    ) -> str | None:
        """
        Normalize a hostname.

        URLs are converted to hostnames. Paths and surrounding punctuation
        are never retained in the host field.
        """

        if value is None:
            return None

        text = _ANSI_PATTERN.sub(
            "",
            str(value),
        ).strip()

        if not text:
            return None

        if "://" in text:

            try:
                parsed = urlparse(
                    text
                )
            except ValueError:
                return None

            hostname = parsed.hostname

        else:
            text = text.strip(
                "\"'`"
            ).rstrip(
                "\"'.,:;"
            )

            # Reject obvious URL paths.
            if "/" in text:
                return None

            try:
                parsed = urlparse(
                    f"//{text}"
                )
                hostname = parsed.hostname
            except ValueError:
                return None

        if not hostname:
            return None

        return hostname.lower().rstrip(
            "."
        )

    @staticmethod
    def _extract_host(
        url: str | None,
    ) -> str | None:
        """
        Extract a hostname from a normalized URL.
        """

        if not url:
            return None

        try:
            parsed = urlparse(
                url
            )
        except ValueError:
            return None

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(
            "."
        )

    @staticmethod
    def _extract_port(
        url: str | None,
    ) -> int | None:
        """
        Extract a valid TCP port from a URL.
        """

        if not url:
            return None

        try:
            parsed = urlparse(
                url
            )
            port = parsed.port
        except ValueError:
            return None

        if port is None:
            return (
                443
                if parsed.scheme.lower()
                == "https"
                else 80
            )

        if 1 <= port <= 65535:
            return port

        return None

    ###########################################################################
    # Target Resolution
    ###########################################################################

    @staticmethod
    def _resolve_target(
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> str:
        """
        Resolve the assessment target from collector context or execution
        metadata.
        """

        context_target = ctx.get(
            "target"
        )

        if context_target:
            return str(
                context_target
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

            execution = metadata.get(
                "execution",
                {},
            )

            if isinstance(
                execution,
                Mapping,
            ):
                target = execution.get(
                    "target"
                )

                if target:
                    return str(
                        target
                    ).strip()

        return ""

    ###########################################################################
    # Public API
    ###########################################################################


__all__ = [
    "TOOL_NAME",
    "OBSERVATION_VULNERABILITY",
    "OBSERVATION_MISCONFIGURATION",
    "OBSERVATION_EXPOSED_RESOURCE",
    "OBSERVATION_CVE",
    "OBSERVATION_SECURITY_ISSUE",
    "NucleiCollector",
]
