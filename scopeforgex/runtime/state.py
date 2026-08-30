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
- Canonical workflow result construction.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from scopeforgex.models.execution_result import ExecutionResult

from .artifacts import Artifact
from .enums import Severity
from .events import RuntimeEvent
from .results import StageResult, WorkflowResult
from .statistics import WorkflowStatistics


###############################################################################
# Time Utilities
###############################################################################


def utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


###############################################################################
# Runtime State
###############################################################################


@dataclass(slots=True)
class RuntimeState:
    """
    Central execution state for an entire ScopeForgeX workflow.

    RuntimeState is the authoritative source of truth for workflow execution.
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

    ###########################################################################
    # Internal
    ###########################################################################

    def _ensure_mutable(self) -> None:
        """
        Raise an error when the runtime state has been frozen.
        """

        if self.frozen:
            raise RuntimeError(
                "RuntimeState has been frozen and can no longer be modified."
            )

    ###########################################################################
    # Events
    ###########################################################################

    def publish(
        self,
        event: RuntimeEvent,
    ) -> None:
        """
        Record a runtime event.
        """

        with self._lock:
            self._ensure_mutable()
            self.events.append(
                event
            )

    ###########################################################################
    # Artifacts
    ###########################################################################

    def add_artifact(
        self,
        artifact: Artifact,
    ) -> None:
        """
        Record an execution artifact.
        """

        with self._lock:
            self._ensure_mutable()

            self.artifacts.append(
                artifact
            )

            self.statistics.increment_artifacts()

    ###########################################################################
    # Tool Results
    ###########################################################################

    def add_tool_result(
        self,
        result: ExecutionResult,
    ) -> None:
        """
        Record an individual tool execution result.
        """

        with self._lock:
            self._ensure_mutable()

            self.tool_results.append(
                result
            )

            self.statistics.increment_tools_executed()

    ###########################################################################
    # Stage Results
    ###########################################################################

    def add_stage_result(
        self,
        result: StageResult,
    ) -> None:
        """
        Record an individual stage result.
        """

        with self._lock:
            self._ensure_mutable()

            self.stage_results.append(
                result
            )

            self.statistics.increment_stages_completed()

    ###########################################################################
    # Warnings
    ###########################################################################

    def add_warning(
        self,
        warning: str,
    ) -> None:
        """
        Record a workflow warning.
        """

        with self._lock:
            self._ensure_mutable()

            self.warnings.append(
                warning
            )

            self.statistics.increment_warnings()

    ###########################################################################
    # Errors
    ###########################################################################

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Record a workflow error.
        """

        with self._lock:
            self._ensure_mutable()

            self.errors.append(
                error
            )

            self.statistics.increment_errors()

    ###########################################################################
    # Workflow Result
    ###########################################################################

    def set_workflow_result(
        self,
        result: WorkflowResult,
    ) -> None:
        """
        Store the canonical workflow result.
        """

        with self._lock:
            self._ensure_mutable()

            self.workflow_result = result

    def build_workflow_result(
        self,
        severity: Severity = Severity.INFO,
    ) -> WorkflowResult:
        """
        Build the canonical final WorkflowResult from RuntimeState.

        RuntimeState is the single source of truth for workflow execution.
        """

        with self._lock:
            if self.errors:
                status = "failed"
            elif self.stage_results:
                statuses = {
                    stage.status
                    for stage in self.stage_results
                }

                if statuses == {"skipped"}:
                    status = "skipped"
                elif "failed" in statuses:
                    status = "failed"
                elif "success" in statuses:
                    status = "success"
                else:
                    status = "failed"
            else:
                status = "skipped"

            started_at = self.started_at
            ended_at = self.finished_at

            duration = 0.0

            if (
                started_at is not None
                and ended_at is not None
            ):
                duration = (
                    ended_at - started_at
                ).total_seconds()

            findings: list[Any] = []

            for stage in self.stage_results:
                findings.extend(
                    stage.findings
                )

            return WorkflowResult(
                target=self.target,
                profile=self.profile,
                status=status,
                stage_results=list(
                    self.stage_results
                ),
                started_at=started_at,
                ended_at=ended_at,
                duration=duration,
                findings=findings,
                artifacts=list(
                    self.artifacts
                ),
                warnings=list(
                    self.warnings
                ),
                errors=list(
                    self.errors
                ),
                metadata={
                    **self.metadata,
                    "workflow_id": str(
                        self.workflow_id
                    ),
                    "schema_version": self.schema_version,
                    "event_count": len(
                        self.events
                    ),
                    "tool_result_count": len(
                        self.tool_results
                    ),
                    "severity": (
                        severity.value
                        if isinstance(
                            severity,
                            Severity,
                        )
                        else str(
                            severity
                        )
                    ),
                },
            )


    def finalize_workflow_result(
        self,
        severity: Severity = Severity.INFO,
    ) -> WorkflowResult:
        """
        Build and store the canonical final WorkflowResult.

        RuntimeState remains the authoritative source of workflow history,
        while workflow_result becomes the canonical aggregate result.
        """

        with self._lock:

            self._ensure_mutable()

            result = self.build_workflow_result(
                severity=severity
            )

            self.workflow_result = result

            return result

    ###########################################################################
    # Lifecycle
    ###########################################################################

    def finish(
        self,
    ) -> None:
        """
        Mark workflow execution complete.
        """

        with self._lock:
            self._ensure_mutable()

            self.finished_at = utc_now()

    def freeze(
        self,
    ) -> None:
        """
        Prevent any further runtime mutations.
        """

        with self._lock:
            self.frozen = True

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serializable representation of the runtime state.
        """

        with self._lock:

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
                "statistics": (
                    self.statistics.as_dict()
                ),
                "events": len(
                    self.events
                ),
                "artifacts": len(
                    self.artifacts
                ),
                "tool_results": len(
                    self.tool_results
                ),
                "stage_results": len(
                    self.stage_results
                ),
                "workflow_result": (
                    self.workflow_result
                    is not None
                ),
                "warnings": list(
                    self.warnings
                ),
                "errors": list(
                    self.errors
                ),
                "frozen": self.frozen,
            }


###############################################################################
# Compatibility Alias
###############################################################################


ExecutionState = RuntimeState


###############################################################################
# Public API
###############################################################################


__all__ = [
    "RuntimeState",
    "ExecutionState",
    "utc_now",
]
