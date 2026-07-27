"""
ScopeForgeX Runtime State
=========================

Defines the RuntimeState object, the authoritative source of truth for
workflow execution.

RuntimeState owns all execution metadata, events, artifacts, results and
statistics. Every component in ScopeForgeX records execution through this
object. Reporters consume RuntimeState instead of reconstructing information
from the filesystem.

Design Principles
-----------------
- Single source of truth.
- Strong typing.
- Thread-safe mutations.
- Standard-library only.
- Independent of CLI/UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from scopeforgex.models.execution_result import ExecutionResult

from .artifacts import Artifact
from .events import RuntimeEvent
from .results import StageResult, WorkflowResult
from .statistics import WorkflowStatistics


def utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


# ============================================================================
# Runtime State
# ============================================================================


@dataclass(slots=True)
class RuntimeState:
    """
    Central execution state for an entire ScopeForgeX workflow.
    """

    workflow_id: UUID = field(
        default_factory=uuid4
    )

    target: str = ""

    profile: str = ""

    schema_version: str = "1.0"

    started_at: datetime = field(
        default_factory=utc_now
    )

    finished_at: datetime | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    statistics: WorkflowStatistics = field(
        default_factory=WorkflowStatistics
    )

    events: list[RuntimeEvent] = field(
        default_factory=list
    )

    artifacts: list[Artifact] = field(
        default_factory=list
    )

    stage_results: list[StageResult] = field(
        default_factory=list
    )

    tool_results: list[ExecutionResult] = field(
        default_factory=list
    )

    workflow_result: WorkflowResult | None = None

    warnings: list[str] = field(
        default_factory=list
    )

    errors: list[str] = field(
        default_factory=list
    )

    frozen: bool = False

    _lock: RLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
    )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure_mutable(self) -> None:
        if self.frozen:
            raise RuntimeError(
                "RuntimeState has been frozen and can no longer be modified."
            )

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def publish(
        self,
        event: RuntimeEvent,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.events.append(event)

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def add_artifact(
        self,
        artifact: Artifact,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.artifacts.append(artifact)
            self.statistics.increment_artifacts()

    # ------------------------------------------------------------------
    # Tool Results
    # ------------------------------------------------------------------

    def add_tool_result(
        self,
        result: ExecutionResult,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.tool_results.append(result)
            self.statistics.increment_tools_executed()

    # ------------------------------------------------------------------
    # Stage Results
    # ------------------------------------------------------------------

    def add_stage_result(
        self,
        result: StageResult,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.stage_results.append(result)
            self.statistics.increment_stages_completed()

    # ------------------------------------------------------------------
    # Warnings
    # ------------------------------------------------------------------

    def add_warning(
        self,
        warning: str,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.warnings.append(warning)
            self.statistics.increment_warnings()

    # ------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------

    def add_error(
        self,
        error: str,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.errors.append(error)
            self.statistics.increment_errors()

    # ------------------------------------------------------------------
    # Workflow Result
    # ------------------------------------------------------------------

    def set_workflow_result(
        self,
        result: WorkflowResult,
    ) -> None:

        with self._lock:
            self._ensure_mutable()
            self.workflow_result = result

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def finish(
        self,
    ) -> None:
        """
        Mark workflow execution complete.
        """

        with self._lock:
            self.finished_at = utc_now()

    def freeze(
        self,
    ) -> None:
        """
        Prevent any further runtime mutations.
        """

        with self._lock:
            self.frozen = True

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def as_dict(
        self,
    ) -> dict[str, Any]:

        return {
            "workflow_id": str(
                self.workflow_id
            ),
            "schema_version": self.schema_version,
            "target": self.target,
            "profile": self.profile,
            "started_at": (
                self.started_at.isoformat()
            ),
            "finished_at": (
                self.finished_at.isoformat()
                if self.finished_at
                else None
            ),
            "metadata": self.metadata,
            "statistics": self.statistics.as_dict(),
            "events": len(self.events),
            "artifacts": len(self.artifacts),
            "tool_results": len(self.tool_results),
            "stage_results": len(self.stage_results),
            "warnings": self.warnings,
            "errors": self.errors,
            "frozen": self.frozen,
        }


__all__ = [
    "RuntimeState",
    "utc_now",
]
