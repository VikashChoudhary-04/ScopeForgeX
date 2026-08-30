"""
ScopeForgeX Subhunt Collector
==============================

Collector for normalizing Subhunt output into the universal ScopeForgeX
Finding model.

Subhunt provides active wordlist-based subdomain discovery. The collector
converts discovered subdomains into structured findings while preserving the
original Subhunt output as evidence.

Pipeline
--------

    Subhunt
        ↓
    Raw Output
        ↓
    Subhunt Collector
        ↓
    SUBDOMAIN Findings
        ↓
    Correlation
        ↓
    Deduplication
        ↓
    Risk Classification
        ↓
    Reporting

Design Principles
-----------------

- The collector does not execute Subhunt.
- Execution belongs to the tool/execution layer.
- The collector only parses and normalizes collected output.
- Every discovered subdomain becomes a structured Finding.
- Original Subhunt output is preserved as evidence.
- Duplicate subdomains are removed deterministically.
- Invalid or empty output is ignored safely.
- Parser behavior is deterministic.
- Collector behavior remains independent from reporting.
- Subhunt remains a distinct capability from Amass.
- A discovered subdomain is an observation, not a vulnerability.

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from scopeforgex.models.finding import (
    DEFAULT_CONFIDENCE,
    DEFAULT_SEVERITY,
    DEFAULT_STATUS,
    Finding,
)


###############################################################################
# Constants
###############################################################################


SOURCE_TOOL = "Subhunt"

DETECTION_METHOD = "Active Subdomain Enumeration"

FINDING_CATEGORY = "subdomain"

FINDING_TYPE = "SUBDOMAIN"

DEFAULT_SEVERITY_VALUE = DEFAULT_SEVERITY

DEFAULT_CONFIDENCE_VALUE = DEFAULT_CONFIDENCE

DEFAULT_STATUS_VALUE = DEFAULT_STATUS


###############################################################################
# Normalization Helpers
###############################################################################


def _text(value: Any) -> str:
    """
    Normalize a value into stripped text.
    """

    if value is None:
        return ""

    return str(value).strip()


def _normalize_subdomain(value: Any) -> str:
    """
    Normalize a discovered subdomain.

    Supported inputs include:

        api.example.com
        api.example.com.
        https://api.example.com
        http://api.example.com:8080

    URL inputs are reduced to their hostname because this collector models
    Subhunt's result as a SUBDOMAIN finding rather than an HTTP endpoint.
    """

    value = _text(value)

    if not value:
        return ""

    candidate = value.strip()

    if "://" in candidate:
        parsed = urlparse(candidate)

        if parsed.hostname:
            candidate = parsed.hostname

    else:
        candidate = candidate.split("/", 1)[0]

        if ":" in candidate:
            parsed = urlparse(
                f"//{candidate}",
            )

            if parsed.hostname:
                candidate = parsed.hostname

    candidate = candidate.strip().lower()

    if candidate.endswith("."):
        candidate = candidate[:-1]

    return candidate


def _is_valid_subdomain(value: str) -> bool:
    """
    Perform conservative validation of a normalized subdomain.

    The collector intentionally does not perform DNS resolution.

    A valid value must:

    - contain at least one character;
    - not contain whitespace;
    - not contain URL path separators;
    - not look like a command-line status message.
    """

    if not value:
        return False

    if any(
        character.isspace()
        for character in value
    ):
        return False

    if "/" in value:
        return False

    if value.startswith(
        (
            "-",
            "[",
            "{",
        )
    ):
        return False

    return True


def _timestamp(
    value: datetime | None,
) -> datetime:
    """
    Return a normalized timestamp.

    Naive timestamps are interpreted as UTC so the Finding model receives a
    timezone-aware timestamp consistently.
    """

    if value is None:
        return datetime.now(
            timezone.utc
        )

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value


###############################################################################
# Subhunt Collector
###############################################################################


class SubhuntCollector:
    """
    Normalize Subhunt output into ScopeForgeX Finding objects.

    The collector accepts either raw textual output or structured records.
    It does not execute Subhunt and does not perform DNS/network activity.
    """

    name = "subhunt_collector"

    source_tool = SOURCE_TOOL

    description = (
        "Normalize Subhunt active subdomain discovery results into "
        "structured SUBDOMAIN findings."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def collect(
        self,
        output: Any,
        *,
        target: str = "",
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Collect findings from Subhunt output.

        Args:
            output:
                Raw Subhunt output or an iterable of structured records.

            target:
                Original assessment target.

            timestamp:
                Observation timestamp. Defaults to the current UTC time.

            metadata:
                Additional metadata to attach to every finding.

        Returns:
            Deterministically ordered list of normalized Finding objects.
        """

        target = _text(target)

        observation_time = _timestamp(
            timestamp
        )

        normalized_metadata = self._metadata(
            metadata
        )

        records = self.parse(
            output
        )

        findings: list[Finding] = []

        seen: set[str] = set()

        for index, record in enumerate(
            records,
            start=1,
        ):
            subdomain = self._record_subdomain(
                record
            )

            if not _is_valid_subdomain(
                subdomain
            ):
                continue

            dedupe_key = subdomain.lower()

            if dedupe_key in seen:
                continue

            seen.add(
                dedupe_key
            )

            evidence = self._record_evidence(
                record
            )

            finding_metadata = dict(
                normalized_metadata
            )

            finding_metadata.update(
                {
                    "finding_type": FINDING_TYPE,
                    "enumeration_method": "wordlist",
                    "collector": self.name,
                }
            )

            finding_id = self._finding_id(
                subdomain,
                index,
            )

            findings.append(
                Finding(
                    finding_id=finding_id,
                    title=(
                        f"Discovered Subdomain: "
                        f"{subdomain}"
                    ),
                    category=FINDING_CATEGORY,
                    severity=DEFAULT_SEVERITY_VALUE,
                    confidence=DEFAULT_CONFIDENCE_VALUE,
                    target=target,
                    host=subdomain,
                    port=None,
                    url=None,
                    parameter=None,
                    description=(
                        "Subhunt discovered the subdomain "
                        f"{subdomain} through active "
                        "wordlist-based subdomain enumeration."
                    ),
                    evidence=evidence,
                    source_tool=SOURCE_TOOL,
                    detection_method=DETECTION_METHOD,
                    timestamp=observation_time,
                    references=[],
                    impact=(
                        "The discovered hostname expands the "
                        "identified attack surface and may expose "
                        "additional services or applications."
                    ),
                    remediation="",
                    status=DEFAULT_STATUS_VALUE,
                    metadata=finding_metadata,
                )
            )

        return findings

    def parse(
        self,
        output: Any,
    ) -> list[Any]:
        """
        Parse Subhunt output into candidate records.

        Raw text is interpreted one result per line.

        Structured mappings are preserved so additional evidence can survive
        normalization.
        """

        if output is None:
            return []

        if isinstance(
            output,
            bytes,
        ):
            output = output.decode(
                "utf-8",
                errors="replace",
            )

        if isinstance(
            output,
            str,
        ):
            return self._parse_text(
                output
            )

        if isinstance(
            Mapping,
            type,
        ):
            if isinstance(
                output,
                Mapping,
            ):
                return [output]

        if isinstance(
            output,
            Iterable,
        ):
            return list(
                output
            )

        return [
            output
        ]

    def collect_many(
        self,
        outputs: Iterable[Any],
        *,
        target: str = "",
        timestamp: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[Finding]:
        """
        Collect findings from multiple Subhunt outputs.

        Duplicate discovered subdomains are removed across all supplied
        outputs.
        """

        if outputs is None:
            return []

        findings: list[Finding] = []

        for output in outputs:
            findings.extend(
                self.collect(
                    output,
                    target=target,
                    timestamp=timestamp,
                    metadata=metadata,
                )
            )

        return self._deduplicate_findings(
            findings
        )

    ###########################################################################
    # Text Parsing
    ###########################################################################

    @staticmethod
    def _parse_text(
        output: str,
    ) -> list[str]:
        """
        Parse plain-text Subhunt output.

        Subhunt results are expected to be line-oriented. Informational,
        progress and empty lines are filtered conservatively.
        """

        records: list[str] = []

        for line in output.splitlines():
            value = line.strip()

            if not value:
                continue

            if SubhuntCollector._is_status_line(
                value
            ):
                continue

            records.append(
                value
            )

        return records

    @staticmethod
    def _is_status_line(
        value: str,
    ) -> bool:
        """
        Identify common non-result Subhunt status/progress lines.

        This deliberately uses conservative patterns to avoid discarding
        legitimate hostnames.
        """

        lowered = value.lower()

        status_prefixes = (
            "tested:",
            "found:",
            "rate:",
            "progress:",
            "testing:",
            "starting",
            "started",
            "finished",
            "completed",
            "error:",
            "warning:",
            "usage:",
            "subhunt ",
        )

        return lowered.startswith(
            status_prefixes
        )

    ###########################################################################
    # Structured Record Handling
    ###########################################################################

    @classmethod
    def _record_subdomain(
        cls,
        record: Any,
    ) -> str:
        """
        Extract a subdomain from a parsed record.
        """

        if isinstance(
            record,
            Mapping,
        ):
            for key in (
                "subdomain",
                "host",
                "hostname",
                "domain",
                "name",
                "target",
            ):
                if key not in record:
                    continue

                value = _normalize_subdomain(
                    record.get(key)
                )

                if value:
                    return value

            return ""

        return _normalize_subdomain(
            record
        )

    @staticmethod
    def _record_evidence(
        record: Any,
    ) -> dict[str, Any]:
        """
        Preserve the originating Subhunt observation as evidence.
        """

        if isinstance(
            record,
            Mapping,
        ):
            return {
                "raw": dict(record),
            }

        return {
            "raw": _text(record),
        }

    ###########################################################################
    # Finding Construction Helpers
    ###########################################################################

    @staticmethod
    def _finding_id(
        subdomain: str,
        index: int,
    ) -> str:
        """
        Build a deterministic finding identifier.

        The ordinal is retained as a collision-safe fallback while the
        normalized hostname forms the human-readable portion.
        """

        safe = "".join(
            character
            if (
                character.isalnum()
                or character in (
                    ".",
                    "-",
                    "_",
                )
            )
            else "-"
            for character in subdomain
        )

        return (
            f"SF-SUBHUNT-{index:04d}-{safe}"
        )

    @staticmethod
    def _metadata(
        metadata: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Copy caller-provided metadata.
        """

        if metadata is None:
            return {}

        return dict(
            metadata
        )

    ###########################################################################
    # Deduplication
    ###########################################################################

    @staticmethod
    def _deduplicate_findings(
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Remove duplicate Subhunt findings by normalized host.

        The first occurrence is preserved.
        """

        result: list[Finding] = []

        seen: set[str] = set()

        for finding in findings:
            host = _normalize_subdomain(
                getattr(
                    finding,
                    "host",
                    "",
                )
            )

            key = host.lower()

            if key:
                if key in seen:
                    continue

                seen.add(
                    key
                )

            result.append(
                finding
            )

        return result


###############################################################################
# Convenience API
###############################################################################


def collect_subhunt_findings(
    output: Any,
    *,
    target: str = "",
    timestamp: datetime | None = None,
    metadata: Mapping[str, Any] | None = None,
    collector: SubhuntCollector | None = None,
) -> list[Finding]:
    """
    Convenience function for collecting Subhunt findings.

    A supplied collector is reused. When no collector is supplied, a
    temporary collector is created.
    """

    collector = (
        collector
        if collector is not None
        else SubhuntCollector()
    )

    return collector.collect(
        output,
        target=target,
        timestamp=timestamp,
        metadata=metadata,
    )


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "SOURCE_TOOL",
    "DETECTION_METHOD",
    "FINDING_CATEGORY",
    "FINDING_TYPE",
    "SubhuntCollector",
    "collect_subhunt_findings",
]
