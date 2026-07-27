"""
ScopeForgeX Runtime Results
===========================

Runtime execution result models.

Extends the canonical ExecutionResult model with
tool, stage and workflow specific information.

v0.5.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scopeforgex.models.execution_result import ExecutionResult

from .artifacts import Artifact
from .enums import Severity, StageType
from .events import RuntimeEvent


###############################################################################
# Tool Result
###############################################################################


@dataclass(slots=True)
class ToolResult(ExecutionResult):
    """
    Result of a single tool execution.
    """

    command: str | None = field(
        default=None,
        kw_only=True,
    )

    category: str | None = field(
        default=None,
        kw_only=True,
    )

    artifacts: tuple[Artifact, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    events: tuple[RuntimeEvent, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    finding_count: int = field(
        default=0,
        kw_only=True,
    )


###############################################################################
# Stage Result
###############################################################################


@dataclass(slots=True)
class StageResult(ExecutionResult):
    """
    Result of a workflow stage.
    """

    stage: StageType = field(
        default=StageType.RECON,
        kw_only=True,
    )

    tools: tuple[ToolResult, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    events: tuple[RuntimeEvent, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    artifacts: tuple[Artifact, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    @property
    def tool_count(self) -> int:
        return len(self.tools)


###############################################################################
# Workflow Result
###############################################################################


@dataclass(slots=True)
class WorkflowResult(ExecutionResult):
    """
    Final workflow execution result.
    """

    workflow_id: str = field(
        default="",
        kw_only=True,
    )

    target: str = field(
        default="",
        kw_only=True,
    )

    profile: str = field(
        default="",
        kw_only=True,
    )

    stages: tuple[StageResult, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    events: tuple[RuntimeEvent, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    artifacts: tuple[Artifact, ...] = field(
        default_factory=tuple,
        kw_only=True,
    )

    severity: Severity = field(
        default=Severity.INFO,
        kw_only=True,
    )

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
    "ToolResult",
    "StageResult",
    "WorkflowResult",
]
