"""
ScopeForgeX Findings Engine
===========================

Universal finding normalization and collection layer.

The findings engine converts tool-specific detections and analyzer
observations into the canonical ScopeForgeX Finding model.

Architecture
------------

Tool / Analyzer
        |
        v
Finding Collector
        |
        v
Universal Finding
        |
        +--> Evidence
        +--> Confidence
        +--> Severity
        +--> Source Tool
        +--> Detection Method
        |
        v
Correlation / Deduplication
        |
        v
Reporting

Design Principles
-----------------

- Every finding uses the universal Finding structure.
- Raw tool output is never treated as the final report.
- Source tool is always preserved.
- Detection method is always preserved.
- Confidence is separate from severity.
- Automated detections are not automatically treated as confirmed.
- Evidence is preserved with the normalized finding.
- Findings can represent vulnerabilities, observations and attack-surface
  information.
- Manual findings use the same universal Finding model.
- Tool-specific command construction does not belong here.

Finding ID
----------

Finding IDs use the canonical ScopeForgeX format:

    SF-001
    SF-002
    SF-003

The collector maintains sequential IDs for findings created during an
assessment.

v1.3.0
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from reporting.models import (
    Finding,
    FindingEvidence,
)

from reporting.severity import (
    normalize_confidence,
    normalize_finding_status,
    normalize_severity,
)


###############################################################################
# Constants
###############################################################################


FINDING_ID_PREFIX = "SF-"


###############################################################################
# Finding ID Generation
###############################################################################


def generate_finding_id(
    number: int,
) -> str:
    """
    Generate a canonical ScopeForgeX finding identifier.

    Examples
    --------
    1  -> SF-001
    2  -> SF-002
    10 -> SF-010
    """

    if number < 1:
        raise ValueError(
            "Finding number must be greater than zero."
        )

    return (
        f"{FINDING_ID_PREFIX}"
        f"{number:03d}"
    )


###############################################################################
# Evidence Conversion
###############################################################################


def _build_evidence(
    value: Any,
) -> FindingEvidence:
    """
    Convert arbitrary evidence input into FindingEvidence.

    Existing FindingEvidence instances are preserved.

    Mapping values are mapped to known evidence fields. Unknown values are
    retained inside ``details`` so evidence is not silently discarded.
    """

    if isinstance(
        value,
        FindingEvidence,
    ):
        return value

    if value is None:
        return FindingEvidence()

    if isinstance(
        value,
        Mapping,
    ):

        data = dict(
            value
        )

        known_fields = {
            "description",
            "request",
            "response",
            "screenshot",
            "file_path",
            "raw_output",
            "artifact_path",
            "source",
            "details",
            "metadata",
        }

        details = data.get(
            "details",
            data.get(
                "metadata",
                {},
            ),
        )

        if not isinstance(
            details,
            Mapping,
        ):
            details = {
                "value": details
            }

        details = dict(
            details
        )

        for key, item in data.items():

            if key not in known_fields:
                details[key] = item

        return FindingEvidence(
            description=str(
                data.get(
                    "description",
                    "",
                )
            ),

            request=str(
                data.get(
                    "request",
                    "",
                )
            ),

            response=str(
                data.get(
                    "response",
                    "",
                )
            ),

            screenshot=str(
                data.get(
                    "screenshot",
                    "",
                )
            ),

            file_path=str(
                data.get(
                    "file_path",
                    "",
                )
            ),

            raw_output=str(
                data.get(
                    "raw_output",
                    "",
                )
            ),

            artifact_path=str(
                data.get(
                    "artifact_path",
                    "",
                )
            ),

            source=str(
                data.get(
                    "source",
                    "",
                )
            ),

            details=details,
        )

    return FindingEvidence(
        description=str(
            value
        )
    )


###############################################################################
# Finding Collector
###############################################################################


class FindingCollector:
    """
    Collect and normalize ScopeForgeX findings.

    The collector is intentionally independent from external tool command
    construction. Tool adapters execute tools and preserve their raw output;
    collectors convert structured observations into the universal Finding
    model.
    """

    def __init__(
        self,
    ) -> None:

        self.findings: list[Finding] = []

        self._next_id = 1

    # ------------------------------------------------------------------
    # ID Management
    # ------------------------------------------------------------------

    def _allocate_finding_id(
        self,
    ) -> str:
        """
        Allocate the next assessment finding ID.
        """

        finding_id = generate_finding_id(
            self._next_id
        )

        self._next_id += 1

        return finding_id

    # ------------------------------------------------------------------
    # Generic Finding
    # ------------------------------------------------------------------

    def add(
        self,
        title: str,
        severity: str,
        target: str,
        source: str,
        description: str = "",
        impact: str = "",
        remediation: str = "",
        evidence: FindingEvidence | None = None,
        confidence: str = "Medium",
        category: str = "security_finding",
        detection_method: str = "Automated Detection",
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        parameter: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        references: Iterable[str] | None = None,
        status: str = "Pending",
        timestamp: datetime | str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Finding:
        """
        Create and store a normalized Finding.

        Detection confidence and validation status are normalized separately
        from severity.
        """

        normalized_references = [
            str(reference).strip()
            for reference in (
                references or []
            )
            if str(reference).strip()
        ]

        if timestamp is None:
            normalized_timestamp: datetime | str = (
                datetime.now(
                    timezone.utc
                )
            )

        else:
            normalized_timestamp = timestamp

        finding = Finding(
            finding_id=self._allocate_finding_id(),

            title=(
                str(title).strip()
                or "Unnamed Finding"
            ),

            category=(
                str(category).strip()
                or "security_finding"
            ),

            severity=normalize_severity(
                severity
            ),

            confidence=normalize_confidence(
                confidence
            ),

            status=normalize_finding_status(
                status
            ),

            target=(
                str(target).strip()
                or "Unknown"
            ),

            host=(
                str(host).strip()
                if host is not None
                and str(host).strip()
                else None
            ),

            port=port,

            url=(
                str(url).strip()
                if url is not None
                and str(url).strip()
                else None
            ),

            parameter=(
                str(parameter).strip()
                if parameter is not None
                and str(parameter).strip()
                else None
            ),

            description=str(
                description
            ).strip(),

            impact=str(
                impact
            ).strip(),

            remediation=str(
                remediation
            ).strip(),

            evidence=(
                evidence
                if evidence is not None
                else FindingEvidence()
            ),

            source_tool=(
                str(source).strip()
                or "unknown"
            ),

            detection_method=(
                str(
                    detection_method
                ).strip()
                or "Automated Detection"
            ),

            timestamp=normalized_timestamp,

            cwe=(
                str(cwe).strip()
                if cwe is not None
                and str(cwe).strip()
                else None
            ),

            cve=(
                str(cve).strip()
                if cve is not None
                and str(cve).strip()
                else None
            ),

            references=normalized_references,

            metadata=dict(
                metadata or {}
            ),
        )

        self.findings.append(
            finding
        )

        return finding

    # ------------------------------------------------------------------
    # Observation Conversion
    # ------------------------------------------------------------------

    def add_observation(
        self,
        observation: Any,
        *,
        source_tool: str | None = None,
        detection_method: str | None = None,
    ) -> Finding:
        """
        Convert a ScopeForgeX-native analyzer observation into a Finding.

        Observations may be mappings or objects exposing ``as_dict()``.
        """

        if isinstance(
            observation,
            Mapping,
        ):

            data = dict(
                observation
            )

        elif hasattr(
            observation,
            "as_dict",
        ):

            data = observation.as_dict()

        else:
            raise TypeError(
                "Observation must be a mapping or expose as_dict()."
            )

        evidence = _build_evidence(
            data.get(
                "evidence"
            )
        )

        return self.add(
            title=data.get(
                "title",
                "Unnamed Finding",
            ),

            severity=data.get(
                "severity",
                "Informational",
            ),

            target=data.get(
                "target",
                "Unknown",
            ),

            source=(
                source_tool
                or data.get(
                    "source_tool",
                    data.get(
                        "source",
                        "scopeforgex",
                    ),
                )
            ),

            description=data.get(
                "description",
                "",
            ),

            impact=data.get(
                "impact",
                "",
            ),

            remediation=data.get(
                "remediation",
                "",
            ),

            evidence=evidence,

            confidence=data.get(
                "confidence",
                "Medium",
            ),

            category=data.get(
                "category",
                "security_finding",
            ),

            detection_method=(
                detection_method
                or data.get(
                    "detection_method",
                    "Automated Detection",
                )
            ),

            host=data.get(
                "host"
            ),

            port=data.get(
                "port"
            ),

            url=data.get(
                "url"
            ),

            parameter=data.get(
                "parameter"
            ),

            cwe=data.get(
                "cwe",
                data.get(
                    "cwe_id"
                ),
            ),

            cve=data.get(
                "cve",
                data.get(
                    "cve_id"
                ),
            ),

            references=data.get(
                "references",
                [],
            ),

            status=data.get(
                "status",
                "Pending",
            ),

            timestamp=data.get(
                "timestamp"
            ),

            metadata=data.get(
                "metadata",
                {},
            ),
        )

    def add_observations(
        self,
        observations: Iterable[Any],
        *,
        source_tool: str | None = None,
        detection_method: str | None = None,
    ) -> list[Finding]:
        """
        Convert multiple analyzer observations into Findings.
        """

        findings: list[Finding] = []

        for observation in observations:

            findings.append(
                self.add_observation(
                    observation,
                    source_tool=source_tool,
                    detection_method=detection_method,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Nuclei Parser
    # ------------------------------------------------------------------

    def parse_nuclei_file(
        self,
        path: str,
    ) -> list[Finding]:
        """
        Parse basic Nuclei text output.

        This method intentionally remains conservative.

        A Nuclei detection is represented as a Pending finding rather than a
        confirmed vulnerability. The original scanner output is preserved as
        evidence.

        Supported basic form:

            [severity] template target
        """

        file = Path(
            path
        )

        if not file.exists():
            return []

        parsed: list[Finding] = []

        with file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as handle:

            for line in handle:

                line = line.strip()

                if not line:
                    continue

                severity = (
                    "Informational"
                )

                lower = line.lower()

                for level in (
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "informational",
                ):

                    if level in lower:
                        severity = level
                        break

                finding = self.add(
                    title="Nuclei Detection",

                    severity=severity,

                    target="Unknown",

                    source="nuclei",

                    description=line,

                    evidence=FindingEvidence(
                        description=(
                            "Original Nuclei output line."
                        ),

                        raw_output=line,

                        source="nuclei",

                        details={
                            "parser": "nuclei_text",
                        },
                    ),

                    confidence="Medium",

                    category="vulnerability",

                    detection_method="Nuclei",

                    status="Pending",
                )

                parsed.append(
                    finding
                )

        return parsed

    # ------------------------------------------------------------------
    # Execution Results
    # ------------------------------------------------------------------

    def from_execution_results(
        self,
        results: Iterable[Any],
    ) -> list[Finding]:
        """
        Convert structured execution-result findings into universal Findings.

        Each execution result may expose:

            tool
            findings

        Individual findings may be mappings or objects exposing ``as_dict()``.
        """

        for result in results:

            tool = str(
                getattr(
                    result,
                    "tool",
                    "unknown",
                )
            ).strip()

            raw_findings = getattr(
                result,
                "findings",
                [],
            )

            if raw_findings is None:
                continue

            for item in raw_findings:

                if isinstance(
                    item,
                    Mapping,
                ):

                    data = dict(
                        item
                    )

                elif hasattr(
                    item,
                    "as_dict",
                ):

                    data = item.as_dict()

                else:
                    continue

                evidence = _build_evidence(
                    data.get(
                        "evidence"
                    )
                )

                self.add(
                    title=data.get(
                        "title",
                        "Unnamed Finding",
                    ),

                    severity=data.get(
                        "severity",
                        "Informational",
                    ),

                    target=data.get(
                        "target",
                        "Unknown",
                    ),

                    source=data.get(
                        "source_tool",
                        data.get(
                            "source",
                            tool,
                        ),
                    ),

                    description=data.get(
                        "description",
                        "",
                    ),

                    impact=data.get(
                        "impact",
                        "",
                    ),

                    remediation=data.get(
                        "remediation",
                        "",
                    ),

                    evidence=evidence,

                    confidence=data.get(
                        "confidence",
                        "Medium",
                    ),

                    category=data.get(
                        "category",
                        "security_finding",
                    ),

                    detection_method=data.get(
                        "detection_method",
                        "Automated Detection",
                    ),

                    host=data.get(
                        "host"
                    ),

                    port=data.get(
                        "port"
                    ),

                    url=data.get(
                        "url"
                    ),

                    parameter=data.get(
                        "parameter"
                    ),

                    cwe=data.get(
                        "cwe",
                        data.get(
                            "cwe_id"
                        ),
                    ),

                    cve=data.get(
                        "cve",
                        data.get(
                            "cve_id"
                        ),
                    ),

                    references=data.get(
                        "references",
                        [],
                    ),

                    status=data.get(
                        "status",
                        "Pending",
                    ),

                    timestamp=data.get(
                        "timestamp"
                    ),

                    metadata=data.get(
                        "metadata",
                        {},
                    ),
                )

        return self.findings

    # ------------------------------------------------------------------
    # Manual Finding
    # ------------------------------------------------------------------

    def add_manual(
        self,
        title: str,
        target: str,
        description: str,
        severity: str = "Informational",
        confidence: str = "Confirmed",
        impact: str = "",
        remediation: str = "",
        evidence: FindingEvidence | None = None,
        host: str | None = None,
        port: int | None = None,
        url: str | None = None,
        parameter: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        references: Iterable[str] | None = None,
        status: str = "Confirmed",
        analyst_notes: str = "",
    ) -> Finding:
        """
        Add a manually validated finding.

        Manual findings use the same universal Finding model as automated
        detections.
        """

        metadata: dict[str, Any] = {}

        if analyst_notes.strip():

            metadata["analyst_notes"] = (
                analyst_notes.strip()
            )

        return self.add(
            title=title,

            severity=severity,

            target=target,

            source="ScopeForgeX",

            description=description,

            impact=impact,

            remediation=remediation,

            evidence=evidence,

            confidence=confidence,

            category="manual_finding",

            detection_method=(
                "Manual Analyst Finding"
            ),

            host=host,

            port=port,

            url=url,

            parameter=parameter,

            cwe=cwe,

            cve=cve,

            references=references,

            status=status,

            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def all(
        self,
    ) -> list[Finding]:
        """
        Return all collected findings.
        """

        return list(
            self.findings
        )

    def count(
        self,
    ) -> int:
        """
        Return the number of collected findings.
        """

        return len(
            self.findings
        )

    def clear(
        self,
    ) -> None:
        """
        Clear the current finding collection.
        """

        self.findings.clear()

        self._next_id = 1


###############################################################################
# Public API
###############################################################################


__all__ = [
    "FINDING_ID_PREFIX",
    "FindingCollector",
    "generate_finding_id",
]
