"""
ScopeForgeX Nuclei Parser
=========================

Parser for Nuclei scanner output.

Responsibilities
----------------
- Parse structured Nuclei JSONL output
- Parse basic Nuclei text output
- Convert Nuclei detections into canonical Finding objects
- Preserve scanner evidence and metadata
- Normalize severity and confidence
- Keep scanner detections pending validation

Design Principles
-----------------
- Nuclei output is evidence, not automatic vulnerability confirmation.
- Every parsed detection becomes the universal ScopeForgeX Finding model.
- Source-tool information is preserved.
- Detection method is preserved.
- Template metadata is retained where available.
- Raw scanner output is preserved as finding evidence.
- Parser failures should not terminate the complete assessment.

v1.3.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from reporting.models import (
    Finding,
    FindingEvidence,
    normalize_confidence,
    normalize_finding_status,
    normalize_severity,
)


###############################################################################
# Constants
###############################################################################


SOURCE_TOOL = "nuclei"

DETECTION_METHOD = "Nuclei"

DEFAULT_SEVERITY = "Informational"

DEFAULT_CONFIDENCE = "Medium"

DEFAULT_STATUS = "Pending"


###############################################################################
# Helpers
###############################################################################


def _string(
    value: Any,
    default: str = "",
) -> str:
    """
    Convert a value into a normalized string.
    """

    if value is None:
        return default

    value = str(value).strip()

    return value if value else default


def _first_string(
    data: Mapping[str, Any],
    keys: Iterable[str],
    default: str = "",
) -> str:
    """
    Return the first non-empty string from the supplied keys.
    """

    for key in keys:

        value = _string(
            data.get(key)
        )

        if value:
            return value

    return default


def _normalize_severity(
    value: Any,
) -> str:
    """
    Normalize Nuclei severity into ScopeForgeX severity terminology.
    """

    return normalize_severity(
        _string(
            value,
            DEFAULT_SEVERITY,
        )
    )


def _normalize_confidence(
    value: Any,
) -> str:
    """
    Normalize confidence into ScopeForgeX terminology.
    """

    return normalize_confidence(
        _string(
            value,
            DEFAULT_CONFIDENCE,
        )
    )


def _normalize_status(
    value: Any,
) -> str:
    """
    Normalize finding validation status.
    """

    return normalize_finding_status(
        _string(
            value,
            DEFAULT_STATUS,
        )
    )


def _extract_host(
    data: Mapping[str, Any],
) -> str:
    """
    Extract the affected host from a Nuclei result.
    """

    return _first_string(
        data,
        (
            "host",
            "ip",
            "hostname",
        ),
    )


def _extract_url(
    data: Mapping[str, Any],
) -> str:
    """
    Extract the affected URL from a Nuclei result.
    """

    return _first_string(
        data,
        (
            "matched-at",
            "matched_at",
            "url",
        ),
    )


def _extract_port(
    data: Mapping[str, Any],
) -> int | None:
    """
    Extract a port when Nuclei provides one.
    """

    value = data.get(
        "port"
    )

    if value is None:
        return None

    try:
        return int(value)
    except (
        TypeError,
        ValueError,
    ):
        return None


def _extract_parameter(
    data: Mapping[str, Any],
) -> str | None:
    """
    Extract a parameter when available.
    """

    value = _first_string(
        data,
        (
            "parameter",
            "param",
        ),
    )

    return value or None


def _extract_template_metadata(
    data: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Extract useful Nuclei template metadata.

    The parser intentionally retains metadata without forcing it into
    universal Finding fields.
    """

    metadata: dict[str, Any] = {}

    template_id = _first_string(
        data,
        (
            "template-id",
            "template_id",
        ),
    )

    if template_id:
        metadata["template_id"] = template_id

    template_path = _first_string(
        data,
        (
            "template-path",
            "template_path",
        ),
    )

    if template_path:
        metadata["template_path"] = template_path

    matcher_name = _first_string(
        data,
        (
            "matcher-name",
            "matcher_name",
        ),
    )

    if matcher_name:
        metadata["matcher_name"] = matcher_name

    extractor_name = _first_string(
        data,
        (
            "extractor-name",
            "extractor_name",
        ),
    )

    if extractor_name:
        metadata["extractor_name"] = extractor_name

    type_value = _first_string(
        data,
        (
            "type",
        ),
    )

    if type_value:
        metadata["nuclei_type"] = type_value

    host = _extract_host(
        data
    )

    if host:
        metadata["host"] = host

    return metadata


def _extract_references(
    data: Mapping[str, Any],
) -> list[str]:
    """
    Extract Nuclei references.
    """

    references = data.get(
        "reference",
        data.get(
            "references",
            [],
        ),
    )

    if references is None:
        return []

    if isinstance(
        references,
        str,
    ):
        return [
            references.strip()
        ] if references.strip() else []

    if not isinstance(
        references,
        Iterable,
    ):
        return []

    output: list[str] = []

    for reference in references:

        value = _string(
            reference
        )

        if value:
            output.append(
                value
            )

    return output


def _extract_tags(
    data: Mapping[str, Any],
) -> list[str]:
    """
    Extract Nuclei template tags.
    """

    tags = data.get(
        "tags",
        [],
    )

    if tags is None:
        return []

    if isinstance(
        tags,
        str,
    ):
        return [
            tag.strip()
            for tag in tags.split(",")
            if tag.strip()
        ]

    if not isinstance(
        tags,
        Iterable,
    ):
        return []

    return [
        _string(tag)
        for tag in tags
        if _string(tag)
    ]


def _extract_cwe(
    data: Mapping[str, Any],
) -> str | None:
    """
    Extract CWE information.
    """

    value = _first_string(
        data,
        (
            "cwe",
            "cwe-id",
            "cwe_id",
        ),
    )

    return value or None


def _extract_cve(
    data: Mapping[str, Any],
) -> str | None:
    """
    Extract CVE information.
    """

    value = _first_string(
        data,
        (
            "cve",
            "cve-id",
            "cve_id",
        ),
    )

    if value:
        return value

    info = data.get(
        "info"
    )

    if isinstance(
        info,
        Mapping,
    ):

        value = _first_string(
            info,
            (
                "cve",
                "cve-id",
                "cve_id",
            ),
        )

        return value or None

    return None


###############################################################################
# Finding Construction
###############################################################################


def finding_from_nuclei(
    data: Mapping[str, Any],
    *,
    raw_output: str = "",
) -> Finding:
    """
    Convert one structured Nuclei result into a canonical Finding.

    Parameters
    ----------
    data:
        Parsed Nuclei JSON object.

    raw_output:
        Original JSONL line. Preserved as evidence whenever supplied.

    Returns
    -------
    Finding
        Canonical ScopeForgeX finding.
    """

    info = data.get(
        "info",
        {},
    )

    if not isinstance(
        info,
        Mapping,
    ):
        info = {}

    title = _first_string(
        data,
        (
            "name",
            "template-name",
            "template_name",
        ),
    )

    if not title:
        title = _first_string(
            info,
            (
                "name",
                "title",
            ),
            "Nuclei Detection",
        )

    severity = _first_string(
        data,
        (
            "severity",
        ),
    )

    if not severity:
        severity = _first_string(
            info,
            (
                "severity",
            ),
            DEFAULT_SEVERITY,
        )

    description = _first_string(
        data,
        (
            "description",
        ),
    )

    if not description:
        description = _first_string(
            info,
            (
                "description",
            ),
        )

    impact = _first_string(
        data,
        (
            "impact",
        ),
    )

    remediation = _first_string(
        data,
        (
            "remediation",
            "solution",
        ),
    )

    if not remediation:
        remediation = _first_string(
            info,
            (
                "remediation",
                "solution",
            ),
        )

    host = _extract_host(
        data
    )

    url = _extract_url(
        data
    )

    port = _extract_port(
        data
    )

    parameter = _extract_parameter(
        data
    )

    template_id = _first_string(
        data,
        (
            "template-id",
            "template_id",
        ),
    )

    if not template_id:
        template_id = "unknown"

    metadata = _extract_template_metadata(
        data
    )

    tags = _extract_tags(
        data
    )

    if tags:
        metadata["tags"] = tags

    metadata["parser"] = "nuclei_jsonl"

    evidence = FindingEvidence(
        description=(
            "Original Nuclei scanner result."
        ),
        raw_output=raw_output,
        artifact_path=_string(
            data.get(
                "template-path",
                "",
            )
        ),
        source=SOURCE_TOOL,
        details=dict(
            data
        ),
    )

    return Finding(
        finding_id="",
        title=title,
        category="vulnerability",
        severity=_normalize_severity(
            severity
        ),
        confidence=_normalize_confidence(
            DEFAULT_CONFIDENCE
        ),
        status=_normalize_status(
            DEFAULT_STATUS
        ),
        target=(
            url
            or host
            or "Unknown"
        ),
        host=host,
        port=port,
        url=url,
        parameter=parameter,
        description=description,
        impact=impact,
        remediation=remediation,
        evidence=evidence,
        source_tool=SOURCE_TOOL,
        detection_method=DETECTION_METHOD,
        cwe=_extract_cwe(
            data
        ),
        cve=_extract_cve(
            data
        ),
        references=_extract_references(
            data
        ),
        metadata=metadata,
    )


###############################################################################
# JSONL Parsing
###############################################################################


def parse_nuclei_json_line(
    line: str,
) -> Finding | None:
    """
    Parse one Nuclei JSONL result line.

    Invalid JSON or non-object values are ignored rather than raising an
    exception so one malformed scanner line cannot terminate reporting.
    """

    raw = line.strip()

    if not raw:
        return None

    try:
        data = json.loads(
            raw
        )

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        return None

    if not isinstance(
        data,
        Mapping,
    ):
        return None

    return finding_from_nuclei(
        data,
        raw_output=raw,
    )


def parse_nuclei_jsonl(
    path: str,
) -> list[Finding]:
    """
    Parse a Nuclei JSONL output file.

    Invalid lines are skipped.
    """

    file = Path(
        path
    )

    if not file.exists():
        return []

    findings: list[Finding] = []

    with file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as handle:

        for line in handle:

            finding = parse_nuclei_json_line(
                line
            )

            if finding is None:
                continue

            findings.append(
                finding
            )

    return findings


###############################################################################
# Text Parsing
###############################################################################


def _detect_text_severity(
    line: str,
) -> str:
    """
    Detect severity from basic Nuclei text output.
    """

    lower = line.lower()

    for severity in (
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "info",
    ):

        if severity in lower:

            if severity == "info":
                return "Informational"

            return severity.title()

    return DEFAULT_SEVERITY


def _extract_text_target(
    line: str,
) -> str:
    """
    Attempt to extract a URL or host from a basic text result.

    The parser remains intentionally conservative and returns the complete
    line when no reliable target can be isolated.
    """

    tokens = line.split()

    for token in tokens:

        cleaned = (
            token
            .strip(
                "[](),"
            )
        )

        if (
            cleaned.startswith(
                "http://"
            )
            or cleaned.startswith(
                "https://"
            )
        ):
            return cleaned

    return "Unknown"


def finding_from_nuclei_text(
    line: str,
) -> Finding:
    """
    Convert one basic Nuclei text result into a canonical Finding.

    This fallback parser is intentionally conservative because Nuclei text
    output is less structured than JSONL.
    """

    raw = line.strip()

    target = _extract_text_target(
        raw
    )

    return Finding(
        finding_id="",
        title="Nuclei Detection",
        category="vulnerability",
        severity=_normalize_severity(
            _detect_text_severity(
                raw
            )
        ),
        confidence=_normalize_confidence(
            DEFAULT_CONFIDENCE
        ),
        status=_normalize_status(
            DEFAULT_STATUS
        ),
        target=target,
        url=(
            target
            if target.startswith(
                (
                    "http://",
                    "https://",
                )
            )
            else ""
        ),
        description=raw,
        evidence=FindingEvidence(
            description=(
                "Original Nuclei text output line."
            ),
            raw_output=raw,
            source=SOURCE_TOOL,
            details={
                "parser": "nuclei_text",
            },
        ),
        source_tool=SOURCE_TOOL,
        detection_method=DETECTION_METHOD,
        metadata={
            "parser": "nuclei_text",
        },
    )


def parse_nuclei_text(
    path: str,
) -> list[Finding]:
    """
    Parse basic Nuclei text output.
    """

    file = Path(
        path
    )

    if not file.exists():
        return []

    findings: list[Finding] = []

    with file.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as handle:

        for line in handle:

            line = line.strip()

            if not line:
                continue

            findings.append(
                finding_from_nuclei_text(
                    line
                )
            )

    return findings


###############################################################################
# Automatic Format Detection
###############################################################################


def parse_nuclei(
    path: str,
) -> list[Finding]:
    """
    Parse a Nuclei output file.

    JSONL is preferred because it preserves structured scanner metadata.
    If the file does not contain valid JSONL results, the parser falls back
    to conservative text parsing.
    """

    file = Path(
        path
    )

    if not file.exists():
        return []

    json_findings = parse_nuclei_jsonl(
        path
    )

    if json_findings:
        return json_findings

    return parse_nuclei_text(
        path
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "finding_from_nuclei",
    "finding_from_nuclei_text",
    "parse_nuclei",
    "parse_nuclei_json_line",
    "parse_nuclei_jsonl",
    "parse_nuclei_text",
]
