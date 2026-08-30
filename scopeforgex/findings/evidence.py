"""
ScopeForgeX Finding Evidence
============================

Evidence management layer for normalized ScopeForgeX findings.

Responsibilities
----------------

- Provide a structured representation for finding evidence.
- Preserve raw and structured evidence.
- Attach evidence to Findings without changing their identity.
- Support evidence provenance.
- Support deterministic evidence serialization.
- Avoid network requests and external tool execution.
- Avoid deciding whether a finding is confirmed.
- Keep evidence management independent from correlation and reporting.

Evidence is deliberately separate from the Finding identity.

For example, two observations may produce the same semantic finding while
having different evidence:

    Nuclei
        -> finding
        -> HTTP response evidence

    Nikto
        -> same finding
        -> scanner output evidence

Deduplication may combine those observations while preserving both pieces of
evidence.

Architecture
------------

Tool
    |
    v
Raw Output
    |
    v
Collector
    |
    v
Normalized Finding
    |
    v
Evidence
    |
    v
Deduplication / Correlation
    |
    v
Reporting

The evidence layer stores what was observed. It does not independently
validate or prove the security condition.

v1.2.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import hashlib
import json


###############################################################################
# Evidence Types
###############################################################################


RAW_OUTPUT = "raw_output"
HTTP_REQUEST = "http_request"
HTTP_RESPONSE = "http_response"
COMMAND_OUTPUT = "command_output"
SCREENSHOT = "screenshot"
FILE = "file"
TEXT = "text"
JSON = "json"
OBSERVATION = "observation"


EVIDENCE_TYPES = (
    RAW_OUTPUT,
    HTTP_REQUEST,
    HTTP_RESPONSE,
    COMMAND_OUTPUT,
    SCREENSHOT,
    FILE,
    TEXT,
    JSON,
    OBSERVATION,
)


###############################################################################
# Evidence
###############################################################################


@dataclass(slots=True)
class FindingEvidence:
    """
    Structured evidence associated with a ScopeForgeX finding.

    Evidence is descriptive rather than authoritative. It records what a
    collector, analyzer, or analyst observed.

    Attributes:
        evidence_id:
            Stable identifier for this evidence object.

        evidence_type:
            Type of evidence being stored.

        content:
            Evidence payload. This may be text, a mapping, a list, or another
            serializable object.

        source_tool:
            Tool or analyzer that produced the evidence.

        source_file:
            Optional path to the original raw evidence file.

        description:
            Human-readable explanation of the evidence.

        collected_at:
            UTC timestamp describing when the evidence was collected.

        metadata:
            Additional provenance or collector-specific information.
    """

    evidence_id: str = ""

    evidence_type: str = TEXT

    content: Any = None

    source_tool: str | None = None

    source_file: str | None = None

    description: str = ""

    collected_at: str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        """
        Normalize the evidence object after initialization.
        """

        self.evidence_type = self._normalize_type(
            self.evidence_type
        )

        if not self.evidence_id:
            self.evidence_id = self.generate_id()

        if self.collected_at is None:
            self.collected_at = utc_timestamp()

    ###########################################################################
    # Identity
    ###########################################################################

    def fingerprint(self) -> str:
        """
        Return a deterministic fingerprint for the evidence content.

        Evidence identity intentionally includes provenance because the same
        textual observation produced by two different tools can still be
        useful evidence from independent sources.
        """

        payload = {
            "evidence_type": self.evidence_type,
            "content": _canonicalize(
                self.content
            ),
            "source_tool": self.source_tool or "",
            "source_file": self.source_file or "",
            "description": self.description or "",
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(
                ",",
                ":",
            ),
            ensure_ascii=False,
        )

        return hashlib.sha256(
            serialized.encode(
                "utf-8"
            )
        ).hexdigest()

    def generate_id(self) -> str:
        """
        Generate a stable evidence identifier.
        """

        return (
            "EV-"
            + self.fingerprint()[:16].upper()
        )

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize evidence into a JSON-compatible dictionary.
        """

        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "content": _canonicalize(
                self.content
            ),
            "source_tool": self.source_tool,
            "source_file": self.source_file,
            "description": self.description,
            "collected_at": self.collected_at,
            "metadata": _canonicalize(
                self.metadata
            ),
        }

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _normalize_type(
        evidence_type: Any,
    ) -> str:
        """
        Normalize an evidence type.
        """

        if evidence_type is None:
            return TEXT

        value = str(
            evidence_type
        ).strip().lower()

        if not value:
            return TEXT

        aliases = {
            "raw": RAW_OUTPUT,
            "stdout": COMMAND_OUTPUT,
            "stderr": COMMAND_OUTPUT,
            "response": HTTP_RESPONSE,
            "request": HTTP_REQUEST,
            "screenshot": SCREENSHOT,
            "image": SCREENSHOT,
            "json": JSON,
            "file": FILE,
            "text": TEXT,
            "observation": OBSERVATION,
        }

        return aliases.get(
            value,
            value,
        )


###############################################################################
# Evidence Manager
###############################################################################


class FindingEvidenceManager:
    """
    Manage evidence attached to ScopeForgeX findings.

    The manager does not alter finding identity, severity, confidence, or
    validation status.
    """

    name = "finding_evidence_manager"

    description = (
        "Manage structured evidence and provenance for ScopeForgeX findings."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def create(
        self,
        *,
        evidence_type: str = TEXT,
        content: Any = None,
        source_tool: str | None = None,
        source_file: str | None = None,
        description: str = "",
        collected_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> FindingEvidence:
        """
        Create a FindingEvidence object.
        """

        return FindingEvidence(
            evidence_type=evidence_type,
            content=content,
            source_tool=source_tool,
            source_file=source_file,
            description=description,
            collected_at=collected_at,
            metadata=dict(
                metadata or {}
            ),
        )

    def attach(
        self,
        finding: Any,
        evidence: FindingEvidence | Any,
    ) -> FindingEvidence:
        """
        Attach evidence to a Finding.

        If a raw evidence object is supplied, it is converted into structured
        FindingEvidence.

        Existing identical evidence is not added twice.
        """

        self._validate_finding(
            finding
        )

        normalized = self._normalize_evidence(
            evidence
        )

        existing = getattr(
            finding,
            "evidence",
            None,
        )

        if existing is None:
            finding.evidence = normalized
            return normalized

        if isinstance(
            existing,
            list,
        ):
            if not self._contains(
                existing,
                normalized,
            ):
                existing.append(
                    normalized
                )
            return normalized

        if self._evidence_equal(
            existing,
            normalized,
        ):
            return normalized

        if hasattr(
            finding,
            "add_evidence",
        ):
            finding.add_evidence(
                normalized
            )
            return normalized

        finding.evidence = [
            existing,
            normalized,
        ]

        return normalized

    def attach_many(
        self,
        finding: Any,
        evidence_items: Iterable[
            FindingEvidence | Any
        ],
    ) -> list[FindingEvidence]:
        """
        Attach multiple evidence objects to a Finding.
        """

        self._validate_finding(
            finding
        )

        if evidence_items is None:
            return []

        attached: list[FindingEvidence] = []

        for evidence in evidence_items:
            attached.append(
                self.attach(
                    finding,
                    evidence,
                )
            )

        return attached

    def collect(
        self,
        finding: Any,
    ) -> list[FindingEvidence]:
        """
        Return all evidence attached to a Finding.

        The returned list is a copy and does not modify the Finding.
        """

        self._validate_finding(
            finding
        )

        evidence = getattr(
            finding,
            "evidence",
            None,
        )

        if evidence is None:
            return []

        if isinstance(
            evidence,
            list,
        ):
            return [
                self._normalize_evidence(
                    item
                )
                for item in evidence
            ]

        return [
            self._normalize_evidence(
                evidence
            )
        ]

    def evidence_count(
        self,
        finding: Any,
    ) -> int:
        """
        Return the number of evidence objects attached to a Finding.
        """

        return len(
            self.collect(
                finding
            )
        )

    ###########################################################################
    # Evidence Conversion
    ###########################################################################

    def _normalize_evidence(
        self,
        evidence: FindingEvidence | Any,
    ) -> FindingEvidence:
        """
        Convert an arbitrary evidence representation into FindingEvidence.
        """

        if isinstance(
            evidence,
            FindingEvidence,
        ):
            return evidence

        if isinstance(
            evidence,
            Mapping,
        ):
            return FindingEvidence(
                evidence_id=str(
                    evidence.get(
                        "evidence_id",
                        "",
                    )
                ).strip(),
                evidence_type=str(
                    evidence.get(
                        "evidence_type",
                        TEXT,
                    )
                ),
                content=evidence.get(
                    "content"
                ),
                source_tool=self._optional_string(
                    evidence.get(
                        "source_tool"
                    )
                ),
                source_file=self._optional_string(
                    evidence.get(
                        "source_file"
                    )
                ),
                description=str(
                    evidence.get(
                        "description",
                        "",
                    )
                    or ""
                ),
                collected_at=self._optional_string(
                    evidence.get(
                        "collected_at"
                    )
                ),
                metadata=dict(
                    evidence.get(
                        "metadata",
                        {},
                    )
                    or {}
                ),
            )

        return FindingEvidence(
            evidence_type=TEXT,
            content=evidence,
        )

    ###########################################################################
    # Deduplication
    ###########################################################################

    @staticmethod
    def _contains(
        evidence_items: list[Any],
        candidate: FindingEvidence,
    ) -> bool:
        """
        Determine whether equivalent evidence is already present.
        """

        candidate_fingerprint = candidate.fingerprint()

        for item in evidence_items:
            try:
                normalized = (
                    item
                    if isinstance(
                        item,
                        FindingEvidence,
                    )
                    else FindingEvidence(
                        content=item
                    )
                )

                if (
                    normalized.fingerprint()
                    == candidate_fingerprint
                ):
                    return True

            except Exception:
                continue

        return False

    @staticmethod
    def _evidence_equal(
        first: Any,
        second: Any,
    ) -> bool:
        """
        Compare evidence safely.
        """

        try:
            first_normalized = (
                first
                if isinstance(
                    first,
                    FindingEvidence,
                )
                else FindingEvidence(
                    content=first
                )
            )

            second_normalized = (
                second
                if isinstance(
                    second,
                    FindingEvidence,
                )
                else FindingEvidence(
                    content=second
                )
            )

            return (
                first_normalized.fingerprint()
                == second_normalized.fingerprint()
            )

        except Exception:
            try:
                return first == second
            except Exception:
                return False

    ###########################################################################
    # Validation
    ###########################################################################

    @staticmethod
    def _validate_finding(
        finding: Any,
    ) -> None:
        """
        Validate that the supplied object can hold finding evidence.

        Importing Finding directly is intentionally avoided here so the
        evidence layer remains usable with compatible Finding implementations.
        """

        if finding is None:
            raise TypeError(
                "finding must not be None."
            )

        if not hasattr(
            finding,
            "evidence",
        ):
            raise TypeError(
                "finding must provide an evidence attribute."
            )

    @staticmethod
    def _optional_string(
        value: Any,
    ) -> str | None:
        """
        Normalize optional string values.
        """

        if value is None:
            return None

        normalized = str(
            value
        ).strip()

        return (
            normalized
            if normalized
            else None
        )


###############################################################################
# Serialization Helpers
###############################################################################


def utc_timestamp() -> str:
    """
    Return the current UTC timestamp in ISO-8601 format.
    """

    return (
        datetime.now(
            timezone.utc
        )
        .replace(
            microsecond=0
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def _canonicalize(
    value: Any,
) -> Any:
    """
    Convert common Python objects into deterministic JSON-compatible values.
    """

    if value is None:
        return None

    if isinstance(
        value,
        FindingEvidence,
    ):
        return value.as_dict()

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): _canonicalize(
                item
            )
            for key, item in sorted(
                value.items(),
                key=lambda item: str(
                    item[0]
                ),
            )
        }

    if isinstance(
        value,
        (list, tuple),
    ):
        return [
            _canonicalize(
                item
            )
            for item in value
        ]

    if isinstance(
        value,
        set,
    ):
        return sorted(
            (
                _canonicalize(
                    item
                )
                for item in value
            ),
            key=lambda item: str(
                item
            ),
        )

    if isinstance(
        value,
        bytes,
    ):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if hasattr(
        value,
        "as_dict",
    ):
        try:
            return _canonicalize(
                value.as_dict()
            )
        except Exception:
            pass

    return str(
        value
    )


###############################################################################
# Convenience API
###############################################################################


_DEFAULT_MANAGER = FindingEvidenceManager()


def create_evidence(
    *,
    evidence_type: str = TEXT,
    content: Any = None,
    source_tool: str | None = None,
    source_file: str | None = None,
    description: str = "",
    collected_at: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> FindingEvidence:
    """
    Create evidence using the default evidence manager.
    """

    return _DEFAULT_MANAGER.create(
        evidence_type=evidence_type,
        content=content,
        source_tool=source_tool,
        source_file=source_file,
        description=description,
        collected_at=collected_at,
        metadata=metadata,
    )


def attach_evidence(
    finding: Any,
    evidence: FindingEvidence | Any,
) -> FindingEvidence:
    """
    Attach evidence using the default evidence manager.
    """

    return _DEFAULT_MANAGER.attach(
        finding,
        evidence,
    )


def attach_evidence_many(
    finding: Any,
    evidence_items: Iterable[
        FindingEvidence | Any
    ],
) -> list[FindingEvidence]:
    """
    Attach multiple evidence objects using the default manager.
    """

    return _DEFAULT_MANAGER.attach_many(
        finding,
        evidence_items,
    )


def get_finding_evidence(
    finding: Any,
) -> list[FindingEvidence]:
    """
    Return all evidence attached to a Finding.
    """

    return _DEFAULT_MANAGER.collect(
        finding
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "RAW_OUTPUT",
    "HTTP_REQUEST",
    "HTTP_RESPONSE",
    "COMMAND_OUTPUT",
    "SCREENSHOT",
    "FILE",
    "TEXT",
    "JSON",
    "OBSERVATION",
    "EVIDENCE_TYPES",
    "FindingEvidence",
    "FindingEvidenceManager",
    "create_evidence",
    "attach_evidence",
    "attach_evidence_many",
    "get_finding_evidence",
    "utc_timestamp",
]
