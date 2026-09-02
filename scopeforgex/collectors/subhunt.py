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

v1.5.0
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
)

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


def _strip_ansi(
    value: str,
) -> str:
    """
    Remove ANSI terminal escape sequences from Subhunt output.
    """

    return re.sub(
        r"\x1b\[[0-9;?]*[ -/]*[@-~]",
        "",
        value,
    )


def _normalize_subdomain(
    value: Any,
) -> str:
    """
    Normalize a discovered Subhunt hostname.

    Supported inputs include:

        api.example.com
        api.example.com.
        [+] api.example.com
        https://api.example.com
        http://api.example.com:8080

    ANSI terminal formatting and common Subhunt result markers are removed
    before hostname normalization.

    Malformed URL-like input is rejected safely rather than aborting the
    complete collection pass.
    """

    value = _text(
        value
    )

    if not value:
        return ""

    candidate = _strip_ansi(
        value
    ).strip()

    # Subhunt commonly prefixes successful discoveries with "[+]".
    if candidate.startswith(
        "[+]"
    ):
        candidate = candidate[3:].strip()

    # Ignore other bracket-style wrappers where possible.
    candidate = candidate.strip()

    if not candidate:
        return ""

    if "://" in candidate:

        try:
            parsed = urlparse(
                candidate
            )

        except ValueError:
            return ""

        if not parsed.hostname:
            return ""

        candidate = parsed.hostname

    else:

        # Raw Subhunt output should normally contain only a hostname.
        # Remove an accidental path suffix.
        candidate = candidate.split(
            "/",
            1,
        )[0].strip()

        if not candidate:
            return ""

        # Handle host:port safely. urlparse() can raise ValueError for
        # malformed bracketed IPv6 input, so the exception is intentionally
        # contained here.
        if ":" in candidate:

            try:
                parsed = urlparse(
                    f"//{candidate}",
                )

            except ValueError:
                return ""

            if not parsed.hostname:
                return ""

            candidate = parsed.hostname

    candidate = _strip_ansi(
        candidate
    ).strip().lower()

    if candidate.endswith("."):
        candidate = candidate[:-1]

    return candidate


def _is_valid_subdomain(
    value: str,
) -> bool:
    """
    Perform conservative validation of a normalized subdomain.

    The collector intentionally does not perform DNS resolution.

    A valid value must:

    - contain at least one character;
    - not contain whitespace;
    - not contain URL path separators;
    - not contain terminal formatting;
    - not contain common command/status markers;
    - not begin with command-line or parser delimiters.
    """

    if not value:
        return False

    if any(
        character.isspace()
        for character in value
    ):
        return False

    if "\x1b" in value:
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

    lowered = value.lower()

    if lowered.startswith(
        (
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


class SubhuntCollector(CollectorBase):
    """
    Normalize Subhunt output into ScopeForgeX Finding objects.

    The collector accepts either raw textual output or structured records.
    It does not execute Subhunt and does not perform DNS/network activity.
    """

    name = "subhunt"
    tool = "subhunt"

    source_tool = SOURCE_TOOL

    description = (
        "Normalize Subhunt active subdomain discovery results into "
        "structured SUBDOMAIN findings."
    )

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
        Parse an already-completed Subhunt execution result.

        The parser is evidence-only. It extracts stdout, feeds it through the
        existing Subhunt normalization logic, and exposes the result as
        universal collector observations.
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

        metadata = context.get(
            "metadata",
            {}
        )

        findings = self.collect_findings(
            str(output),
            target=target,
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

    def collect_findings(
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

        target = _text(
            target
        )

        observation_time = _timestamp(
            timestamp
        )

        normalized_metadata = self._metadata(
            metadata
        )

        records = self._parse_output(
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

            finding_data = {
                "title": (
                    f"Discovered Subdomain: "
                    f"{subdomain}"
                ),
                "category": FINDING_CATEGORY,
                "severity": DEFAULT_SEVERITY_VALUE,
                "confidence": DEFAULT_CONFIDENCE_VALUE,
                "target": target,
                "host": subdomain,
                "port": None,
                "url": None,
                "parameter": None,
                "description": (
                    "Subhunt discovered the subdomain "
                    f"{subdomain} through active "
                    "wordlist-based subdomain enumeration."
                ),
                "evidence": evidence,
                "source_tool": SOURCE_TOOL,
                "detection_method": DETECTION_METHOD,
                "timestamp": observation_time,
                "references": [],
                "impact": (
                    "The discovered hostname expands the "
                    "identified attack surface and may expose "
                    "additional services or applications."
                ),
                "remediation": "",
                "status": DEFAULT_STATUS_VALUE,
                "metadata": finding_metadata,
            }

            findings.append(
                Finding.from_mapping(
                    finding_data,
                    finding_id=finding_id,
                )
            )

        return findings

    def _parse_output(
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
            output,
            Mapping,
        ):

            return [
                output
            ]

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
                self.collect_findings(
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

        ANSI terminal formatting and successful-result markers are removed
        before records reach hostname normalization.
        """

        records: list[str] = []

        for line in output.splitlines():

            value = _strip_ansi(
                line
            ).strip()

            if not value:
                continue

            # Successful Subhunt lines are commonly emitted as:
            #
            #     [+] api.example.com
            #
            if value.startswith(
                "[+]"
            ):

                value = value[3:].strip()

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
                    record.get(
                        key
                    )
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
                "raw": dict(
                    record
                ),
            }

        return {
            "raw": _text(
                record
            ),
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

    return collector.collect_findings(
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
