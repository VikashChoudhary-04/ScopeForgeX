"""
ScopeForgeX Runtime Results
===========================

Defines immutable execution result models used by the ScopeForgeX runtime.

Result objects represent the outcome of workflow, stage and tool execution.
They are the authoritative runtime records consumed by reporting, storage and
future dashboard components.

Design Principles
-----------------
- Immutable dataclasses.
- Strong typing.
- Standard-library only.
- JSON serialization friendly.
- Thread-safe.
- Independent of CLI/UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from .artifacts import Artifact
from .enums import Severity, StageType, Status
from .events import RuntimeEvent


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


# ============================================================================
# Base Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """
    Base execution result.
    """

    name: str

    status: Status

    started_at: datetime

    finished_at: datetime

    elapsed: float

    result_id: UUID = field(default_factory=uuid4)

    warnings: tuple[str, ...] = ()

    errors: tuple[str, ...] = ()

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def successful(self) -> bool:
        return self.status is Status.COMPLETED

    @property
    def failed(self) -> bool:
        return self.status is Status.FAILED

    def as_dict(self) -> dict[str, Any]:
        return {
            "result_id": str(self.result_id),
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "elapsed": self.elapsed,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "metadata": self.metadata,
        }


# ============================================================================
# Tool Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class ToolResult(ExecutionResult):
    """
    Result of a single tool execution.
    """

    command: str | None = None

    exit_code: int | None = None

    category: str | None = None

    artifacts: tuple[Artifact, ...] = ()

    events: tuple[RuntimeEvent, ...] = ()

    findings: int = 0


# ============================================================================
# Stage Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class StageResult(ExecutionResult):
    """
    Result of a workflow stage.
    """

    stage: StageType = StageType.RECON

    tools: tuple[ToolResult, ...] = ()

    events: tuple[RuntimeEvent, ...] = ()

    artifacts: tuple[Artifact, ...] = ()

    @property
    def tool_count(self) -> int:
        return len(self.tools)


# ============================================================================
# Workflow Result
# ============================================================================


@dataclass(frozen=True, slots=True)
class WorkflowResult(ExecutionResult):
    """
    Final workflow execution result.
    """

    workflow_id: str

    target: str

    profile: str

    stages: tuple[StageResult, ...] = ()

    events: tuple[RuntimeEvent, ...] = ()

    artifacts: tuple[Artifact, ...] = ()

    severity: Severity = Severity.INFO

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def event_count(self) -> int:
        return len(self.events)


__all__ = [
    "ExecutionResult",
    "StageResult",
    "ToolResult",
    "WorkflowResult",
    "utc_now",
]
