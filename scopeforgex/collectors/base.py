"""
ScopeForgeX Collector Base
==========================

Canonical collector abstraction for ScopeForgeX tool output.

Collectors are responsible for converting raw tool output into structured
observations that can later be normalized into ScopeForgeX Findings.

Architecture
------------

Tool Adapter
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
Collector
    ↓
Structured Observations
    ↓
Finding Normalizer
    ↓
Finding
    ↓
Correlation / Deduplication
    ↓
Report

Design Principles
-----------------
- Raw tool output is never discarded.
- Collectors do not execute tools.
- Collectors do not construct commands.
- Collectors do not assign final risk unless the source explicitly provides it.
- Collectors should be deterministic.
- Each external tool gets its own collector implementation.
- Native ScopeForgeX analyzers may also use this abstraction.
- Collector failures must not corrupt the original execution result.
- Collector observations support both attack-surface data and richer
  security-finding metadata.
- ``BaseCollector`` remains a compatibility alias for ``CollectorBase``.

v3.0.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


###############################################################################
# Collector Observation
###############################################################################


@dataclass(slots=True)
class CollectorObservation:
    """
    Structured observation extracted from raw tool evidence.

    An observation is not necessarily a vulnerability.

    The schema intentionally supports both lightweight attack-surface
    observations and richer security observations that already have finding
    metadata available from the source tool.

    Examples:

        Nmap
            OPEN_PORT

        httpx
            HTTP_SERVICE

        WhatWeb
            TECHNOLOGY

        Katana
            ENDPOINT

        Nuclei
            VULNERABILITY
    """

    # ========================================================================
    # Observation Identity
    # ========================================================================

    observation_type: str

    value: Any = None

    # ========================================================================
    # Finding-Compatible Metadata
    # ========================================================================

    title: str = ""

    description: str = ""

    impact: str = ""

    remediation: str = ""

    severity: str = "Informational"

    confidence: str = "Informational"

    status: str = "Pending"

    # ========================================================================
    # Affected Asset
    # ========================================================================

    target: str | None = None

    host: str | None = None

    port: int | None = None

    url: str | None = None

    parameter: str | None = None

    # ========================================================================
    # Evidence / Provenance
    # ========================================================================

    evidence: Any = None

    source_tool: str = ""

    detection_method: str = ""

    # ========================================================================
    # Security References
    # ========================================================================

    cwe: str | None = None

    cve: str | None = None

    references: list[str] = field(
        default_factory=list
    )

    # ========================================================================
    # Additional Metadata
    # ========================================================================

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize basic observation fields.

        The collector remains intentionally permissive: tool-specific
        collectors may supply richer values and the Finding Normalizer is
        responsible for canonical finding normalization.
        """

        self.observation_type = str(
            self.observation_type
        ).strip()

        self.title = str(
            self.title or ""
        ).strip()

        self.description = str(
            self.description or ""
        ).strip()

        self.impact = str(
            self.impact or ""
        ).strip()

        self.remediation = str(
            self.remediation or ""
        ).strip()

        self.severity = str(
            self.severity or "Informational"
        ).strip()

        self.confidence = str(
            self.confidence or "Informational"
        ).strip()

        self.status = str(
            self.status or "Pending"
        ).strip()

        self.source_tool = str(
            self.source_tool or ""
        ).strip()

        self.detection_method = str(
            self.detection_method or ""
        ).strip()

        if self.target is not None:
            self.target = str(
                self.target
            ).strip()

        if self.host is not None:
            self.host = str(
                self.host
            ).strip()

        if self.url is not None:
            self.url = str(
                self.url
            ).strip()

        if self.parameter is not None:
            self.parameter = str(
                self.parameter
            ).strip()

        if self.cwe is not None:
            self.cwe = str(
                self.cwe
            ).strip() or None

        if self.cve is not None:
            self.cve = str(
                self.cve
            ).strip() or None

        if self.references is None:
            self.references = []

        else:
            self.references = [
                str(reference).strip()
                for reference in self.references
                if str(reference).strip()
            ]

        if self.metadata is None:
            self.metadata = {}

        elif not isinstance(
            self.metadata,
            dict,
        ):
            self.metadata = dict(
                self.metadata
            )

        else:
            self.metadata = dict(
                self.metadata
            )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the observation.
        """

        return {
            "observation_type": (
                self.observation_type
            ),
            "value": self.value,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "source_tool": self.source_tool,
            "detection_method": (
                self.detection_method
            ),
            "cwe": self.cwe,
            "cve": self.cve,
            "references": list(
                self.references
            ),
            "metadata": dict(
                self.metadata
            ),
        }


###############################################################################
# Collector Result
###############################################################################


@dataclass(slots=True)
class CollectorResult:
    """
    Result produced by a collector.

    The result preserves both:

    - structured observations
    - collector warnings/errors
    - source evidence references
    """

    tool: str

    observations: list[CollectorObservation] = field(
        default_factory=list
    )

    warnings: list[str] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )

    source_files: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def success(
        self,
    ) -> bool:
        """
        Return whether collection completed without collector errors.
        """

        return not self.errors

    @property
    def observation_count(
        self,
    ) -> int:
        """
        Return the number of collected observations.
        """

        return len(
            self.observations
        )

    def add_observation(
        self,
        observation: CollectorObservation,
    ) -> None:
        """
        Add one structured observation.
        """

        if not isinstance(
            observation,
            CollectorObservation,
        ):
            raise TypeError(
                "CollectorResult observations must be "
                "CollectorObservation objects."
            )

        self.observations.append(
            observation
        )

    def add_warning(
        self,
        warning: str,
    ) -> None:
        """
        Add a non-fatal collector warning.
        """

        if warning:
            self.warnings.append(
                str(
                    warning
                )
            )

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Add a collector error.
        """

        if error:
            self.errors.append(
                str(
                    error
                )
            )

    def add_source_file(
        self,
        path: str | Path,
    ) -> None:
        """
        Record a raw evidence file consumed by the collector.
        """

        normalized = str(
            path
        )

        if normalized not in self.source_files:
            self.source_files.append(
                normalized
            )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the collector result.
        """

        return {
            "tool": self.tool,
            "success": self.success,
            "observation_count": (
                self.observation_count
            ),
            "observations": [
                observation.as_dict()
                for observation in self.observations
            ],
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "source_files": list(
                self.source_files
            ),
            "metadata": dict(
                self.metadata
            ),
        }


###############################################################################
# Collector Base
###############################################################################


class CollectorBase(ABC):
    """
    Abstract base class for ScopeForgeX collectors.

    A collector consumes already-produced execution evidence.

    It must never invoke an external executable itself.
    """

    name: str = ""

    tool: str = ""

    description: str = ""

    supported_input_types: tuple[str, ...] = (
        "execution_result",
    )

    def __init__(
        self,
    ) -> None:
        """
        Validate collector metadata at construction time.

        A number of migrated collectors historically defined ``name`` but
        omitted ``tool``. For compatibility, the canonical tool name defaults
        to ``name`` when necessary.
        """

        if not self.name:
            raise ValueError(
                "Collector name cannot be empty."
            )

        if not self.tool:
            self.tool = self.name

        self.name = str(
            self.name
        ).strip()

        self.tool = str(
            self.tool
        ).strip()

        if not self.name:
            raise ValueError(
                "Collector name cannot be empty."
            )

        if not self.tool:
            raise ValueError(
                "Collector tool cannot be empty."
            )

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    def collector_name(
        self,
    ) -> str:
        """
        Return the canonical collector name.
        """

        return self.name

    @property
    def source_tool(
        self,
    ) -> str:
        """
        Return the canonical source tool name.
        """

        return self.tool

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return collector metadata.
        """

        return {
            "name": self.name,
            "tool": self.tool,
            "description": self.description,
            "supported_input_types": (
                list(
                    self.supported_input_types
                )
            ),
        }

    # ------------------------------------------------------------------
    # Input Validation
    # ------------------------------------------------------------------

    def validate_input(
        self,
        execution_result: Any,
    ) -> None:
        """
        Validate the execution result before collection.

        Subclasses may extend this method when they require additional
        tool-specific information.
        """

        if execution_result is None:
            raise ValueError(
                f"{self.name}: execution result cannot be None."
            )

    # ------------------------------------------------------------------
    # Evidence Discovery
    # ------------------------------------------------------------------

    def get_artifacts(
        self,
        execution_result: Any,
    ) -> list[Path]:
        """
        Return filesystem artifacts associated with an execution result.

        The method supports the common ExecutionResult artifact conventions
        used by ScopeForgeX.
        """

        artifacts = getattr(
            execution_result,
            "artifacts",
            (),
        )

        if artifacts is None:
            return []

        result: list[Path] = []

        for artifact in artifacts:

            path: Any = artifact

            if hasattr(
                artifact,
                "path",
            ):
                path = artifact.path

            if path is None:
                continue

            result.append(
                Path(
                    str(
                        path
                    )
                )
            )

        return result

    # ------------------------------------------------------------------
    # Collection Context
    # ------------------------------------------------------------------

    def build_context(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build an isolated collector context.

        The caller's context is never mutated.
        """

        context = dict(
            ctx or {}
        )

        context.setdefault(
            "tool",
            self.tool,
        )

        context.setdefault(
            "collector",
            self.name,
        )

        context.setdefault(
            "execution_result",
            execution_result,
        )

        context.setdefault(
            "artifacts",
            self.get_artifacts(
                execution_result
            ),
        )

        return context

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def collect(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any] | None = None,
    ) -> CollectorResult:
        """
        Collect structured observations from an execution result.

        This is the canonical CollectorBase entry point.
        """

        self.validate_input(
            execution_result
        )

        result = CollectorResult(
            tool=self.tool
        )

        context = self.build_context(
            execution_result,
            ctx,
        )

        try:
            observations = self.parse(
                execution_result,
                context,
            )

        except Exception as exc:
            result.add_error(
                (
                    f"{self.name} collector failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

            return result

        if observations is None:
            observations = []

        for observation in observations:

            if not isinstance(
                observation,
                CollectorObservation,
            ):
                result.add_error(
                    (
                        f"{self.name} collector returned "
                        "an invalid observation object."
                    )
                )
                continue

            result.add_observation(
                observation
            )

        for path in context.get(
            "artifacts",
            [],
        ):

            normalized = str(
                path
            )

            if normalized not in result.source_files:
                result.source_files.append(
                    normalized
                )

        result.metadata.update(
            self.build_metadata(
                execution_result,
                context,
            )
        )

        return result

    # ------------------------------------------------------------------
    # Parser Contract
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse tool-specific output into structured observations.

        Subclasses must implement this method.

        No external command execution should occur here.
        """

        raise NotImplementedError

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def build_metadata(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Build generic collector metadata.

        Tool-specific collectors may override this method.
        """

        return {
            "tool": self.tool,
            "collector": self.name,
            "execution_success": bool(
                getattr(
                    execution_result,
                    "success",
                    False,
                )
            ),
        }


###############################################################################
# Compatibility Alias
###############################################################################


# Several migrated collectors historically imported ``BaseCollector``.
# Keep the alias so the canonical base class remains backwards compatible
# while the project converges on ``CollectorBase``.
BaseCollector = CollectorBase


###############################################################################
# Utility Functions
###############################################################################


def read_text_file(
    path: str | Path,
) -> str:
    """
    Read a collector input file safely.

    Returns an empty string when the file cannot be read.
    """

    file_path = Path(
        path
    )

    if not file_path.is_file():
        return ""

    try:
        return file_path.read_text(
            encoding="utf-8",
            errors="ignore",
        )

    except OSError:
        return ""


def read_lines(
    path: str | Path,
) -> list[str]:
    """
    Read non-empty lines from a collector input file.
    """

    content = read_text_file(
        path
    )

    if not content:
        return []

    return [
        line.strip()
        for line in content.splitlines()
        if line.strip()
    ]


def first_existing_artifact(
    artifacts: list[Path] | tuple[Path, ...],
) -> Path | None:
    """
    Return the first existing artifact from a sequence.
    """

    for artifact in artifacts:

        if artifact.is_file():
            return artifact

    return None


###############################################################################
# Public API
###############################################################################


__all__ = [
    "CollectorObservation",
    "CollectorResult",
    "CollectorBase",
    "BaseCollector",
    "read_text_file",
    "read_lines",
    "first_existing_artifact",
]
