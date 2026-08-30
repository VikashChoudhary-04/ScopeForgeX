"""
ScopeForgeX — Execution Result Model
====================================

Canonical result object returned by executable ScopeForgeX tools.

The model provides:

- Success/failure/skipped execution state
- stdout/stderr capture
- Artifact tracking
- Structured finding/observation capture
- Warnings
- Errors
- Execution metadata
- Timing information
- Serialization helpers

Architecture
------------

Tool Adapter
    ↓
Execution Layer
    ↓
ExecutionResult
    ↓
Collector / Finding Pipeline
    ↓
Correlation / Deduplication
    ↓
Reporting

Design Principles
-----------------

- Every executable tool returns a predictable result structure.
- Execution state is separate from assessment findings.
- Raw process output is preserved.
- Structured findings are preserved without forcing premature normalization.
- Artifacts are tracked explicitly.
- Warnings and errors remain distinct.
- Timing information is timezone-aware.
- Serialization is deterministic and JSON-compatible where possible.
- The model does not execute tools or perform network requests.
- The model remains independent from reporting and risk classification.

v1.3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


###############################################################################
# Helpers
###############################################################################


def utc_now() -> datetime:
    """
    Return the current UTC timestamp as a timezone-aware datetime.
    """

    return datetime.now(
        timezone.utc
    )


def _normalize_text(
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


def _normalize_timestamp(
    value: datetime,
) -> datetime:
    """
    Normalize a timestamp into a timezone-aware datetime.

    Naive datetimes are interpreted as UTC.

    Aware datetimes are preserved and converted to UTC so execution timing
    remains deterministic across timezone boundaries.
    """

    if not isinstance(
        value,
        datetime,
    ):
        raise TypeError(
            "Execution timestamps must be datetime objects."
        )

    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


###############################################################################
# Execution Result
###############################################################################


@dataclass(slots=True)
class ExecutionResult:
    """
    Standard result returned by every executable ScopeForgeX tool.

    ``findings`` intentionally accepts ``Any`` because execution results may
    contain raw observations before they enter the universal Finding
    normalization pipeline.
    """

    # ========================================================================
    # Identity
    # ========================================================================

    tool: str

    capability: str

    # ========================================================================
    # Execution State
    # ========================================================================

    success: bool = False

    # ========================================================================
    # Captured Process Output
    # ========================================================================

    stdout: str = ""

    stderr: str = ""

    # ========================================================================
    # Structured Assessment Data
    # ========================================================================

    artifacts: list[str] = field(
        default_factory=list,
    )

    findings: list[Any] = field(
        default_factory=list,
    )

    warnings: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    # ========================================================================
    # Timing
    # ========================================================================

    started_at: datetime = field(
        default_factory=utc_now,
    )

    finished_at: datetime | None = None

    duration: float = 0.0

    # ========================================================================
    # Initialization
    # ========================================================================

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize and validate the execution result.
        """

        self.tool = _normalize_text(
            self.tool
        )

        self.capability = _normalize_text(
            self.capability
        )

        if not self.tool:
            raise ValueError(
                "ExecutionResult tool cannot be empty."
            )

        if not self.capability:
            raise ValueError(
                "ExecutionResult capability cannot be empty."
            )

        self.success = bool(
            self.success
        )

        self.stdout = _normalize_text(
            self.stdout
        )

        self.stderr = _normalize_text(
            self.stderr
        )

        self.artifacts = self._normalize_string_list(
            self.artifacts,
            "artifacts",
        )

        self.warnings = self._normalize_string_list(
            self.warnings,
            "warnings",
        )

        self.errors = self._normalize_string_list(
            self.errors,
            "errors",
        )

        if self.findings is None:
            self.findings = []
        else:
            self.findings = list(
                self.findings
            )

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

        self.started_at = _normalize_timestamp(
            self.started_at
        )

        if self.finished_at is not None:
            self.finished_at = _normalize_timestamp(
                self.finished_at
            )

        self.duration = self._normalize_duration(
            self.duration
        )

    # ========================================================================
    # Runtime Properties
    # ========================================================================

    @property
    def status(
        self,
    ) -> str:
        """
        Return the normalized execution status.

        Supported states:

        - success
        - failed
        - skipped

        A skipped result is represented explicitly through metadata while
        ``success`` remains false.
        """

        if (
            self.metadata.get(
                "status"
            )
            == "skipped"
        ):
            return "skipped"

        if self.success:
            return "success"

        return "failed"

    @property
    def completed(
        self,
    ) -> bool:
        """
        Return whether execution has been finalized.
        """

        return self.finished_at is not None

    # ========================================================================
    # Mutation Helpers
    # ========================================================================

    def add_artifact(
        self,
        artifact: str,
    ) -> None:
        """
        Add an artifact path if it is not already present.
        """

        artifact_value = _normalize_text(
            artifact
        )

        if not artifact_value:
            return

        if artifact_value not in self.artifacts:
            self.artifacts.append(
                artifact_value
            )

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Add an execution error.
        """

        error_value = _normalize_text(
            error
        )

        if not error_value:
            return

        self.errors.append(
            error_value
        )

    def add_warning(
        self,
        warning: str,
    ) -> None:
        """
        Add an execution warning.
        """

        warning_value = _normalize_text(
            warning
        )

        if not warning_value:
            return

        self.warnings.append(
            warning_value
        )

    def add_finding(
        self,
        finding: Any,
    ) -> None:
        """
        Add a structured finding or raw observation.
        """

        if finding is None:
            return

        self.findings.append(
            finding
        )

    def add_metadata(
        self,
        key: str,
        value: Any,
    ) -> None:
        """
        Add or update one execution metadata field.
        """

        key = _normalize_text(
            key
        )

        if not key:
            raise ValueError(
                "Execution metadata key cannot be empty."
            )

        self.metadata[
            key
        ] = value

    # ========================================================================
    # Constructors
    # ========================================================================

    @classmethod
    def success_result(
        cls,
        tool: str,
        capability: str,
        artifacts: Any = None,
        findings: Any = None,
        metadata: Any = None,
        warnings: Any = None,
        stdout: str = "",
        stderr: str = "",
    ) -> ExecutionResult:
        """
        Create a successful execution result.

        The result is initialized with an execution start timestamp and is
        finalized immediately. Callers representing a real execution may
        instead instantiate the model and call ``finalize()`` when execution
        actually completes.
        """

        now = utc_now()

        result = cls(
            tool=tool,
            capability=capability,
            success=True,
            stdout=stdout,
            stderr=stderr,
            artifacts=list(
                artifacts or []
            ),
            findings=list(
                findings or []
            ),
            warnings=list(
                warnings or []
            ),
            errors=[],
            metadata=dict(
                metadata or {}
            ),
            started_at=now,
            finished_at=now,
            duration=0.0,
        )

        return result

    @classmethod
    def failure(
        cls,
        tool: str,
        capability: str,
        error: str,
        artifacts: Any = None,
        metadata: Any = None,
        stdout: str = "",
        stderr: str = "",
    ) -> ExecutionResult:
        """
        Create a failed execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            stdout=stdout,
            stderr=stderr,
            artifacts=list(
                artifacts or []
            ),
            findings=[],
            warnings=[],
            errors=[
                _normalize_text(
                    error
                )
            ],
            metadata=dict(
                metadata or {}
            ),
            started_at=now,
            finished_at=now,
            duration=0.0,
        )

    @classmethod
    def skipped(
        cls,
        tool: str,
        capability: str,
        reason: str,
    ) -> ExecutionResult:
        """
        Create a skipped execution result.
        """

        reason_value = _normalize_text(
            reason
        )

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            stdout="",
            stderr="",
            artifacts=[],
            findings=[],
            warnings=[
                reason_value
            ]
            if reason_value
            else [],
            errors=[],
            metadata={
                "status": "skipped",
                "skip_reason": reason_value,
            },
            started_at=now,
            finished_at=now,
            duration=0.0,
        )

    # ========================================================================
    # Timing
    # ========================================================================

    def finalize(
        self,
        finished_at: datetime | None = None,
    ) -> None:
        """
        Finalize execution timing.

        Args:
            finished_at:
                Optional completion timestamp.

        Naive timestamps are interpreted as UTC. All stored timestamps are
        normalized to UTC.
        """

        completion_time = (
            finished_at
            if finished_at is not None
            else utc_now()
        )

        completion_time = _normalize_timestamp(
            completion_time
        )

        self.finished_at = completion_time

        self.duration = max(
            0.0,
            (
                completion_time
                - self.started_at
            ).total_seconds(),
        )

    # ========================================================================
    # Serialization
    # ========================================================================

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Convert the execution result into a JSON-compatible dictionary.

        Structured objects exposing ``as_dict()`` are serialized through that
        interface. Dictionaries are copied so serialization does not expose
        the internal metadata container.
        """

        serialized_findings: list[Any] = []

        for finding in self.findings:

            if hasattr(
                finding,
                "as_dict",
            ):
                serialized_findings.append(
                    finding.as_dict()
                )

            elif isinstance(
                finding,
                dict,
            ):
                serialized_findings.append(
                    dict(
                        finding
                    )
                )

            else:
                serialized_findings.append(
                    finding
                )

        return {
            "tool": self.tool,
            "capability": self.capability,
            "success": self.success,
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": list(
                self.artifacts
            ),
            "findings": serialized_findings,
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat()
                if self.finished_at is not None
                else None
            ),
            "duration": self.duration,
        }

    # ========================================================================
    # Normalization Helpers
    # ========================================================================

    @staticmethod
    def _normalize_string_list(
        values: Any,
        field_name: str,
    ) -> list[str]:
        """
        Normalize a collection of string values.

        Empty entries are removed. Duplicate entries are preserved because
        warnings and errors may legitimately occur more than once.
        """

        if values is None:
            return []

        if isinstance(
            values,
            str,
        ):
            values = [
                values
            ]

        try:
            iterator = iter(
                values
            )
        except TypeError as exc:
            raise TypeError(
                f"ExecutionResult {field_name} must be iterable."
            ) from exc

        result: list[str] = []

        for value in iterator:

            normalized = _normalize_text(
                value
            )

            if normalized:
                result.append(
                    normalized
                )

        return result

    @staticmethod
    def _normalize_duration(
        value: Any,
    ) -> float:
        """
        Normalize execution duration into a non-negative float.
        """

        if value is None:
            return 0.0

        try:
            duration = float(
                value
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"Invalid execution duration: {value}"
            ) from exc

        if duration < 0:
            return 0.0

        return duration


###############################################################################
# Public API
###############################################################################


__all__ = [
    "ExecutionResult",
    "utc_now",
]
