"""
ScopeForgeX Runtime Events
==========================

Defines immutable runtime events emitted during workflow execution.

Events provide an audit trail for:
- workflow lifecycle
- stage execution
- tool execution
- warnings
- errors

v0.5.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID


###############################################################################
# Helpers
###############################################################################


def utc_now() -> datetime:
    """
    Return current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


###############################################################################
# Base Event
###############################################################################


@dataclass(
    slots=True
)
class RuntimeEvent:
    """
    Base runtime event.

    timestamp is keyword-only to prevent dataclass inheritance ordering
    conflicts when child events define required fields.
    """

    timestamp: datetime = field(
        default_factory=utc_now,
        kw_only=True,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
        kw_only=True,
    )


###############################################################################
# Workflow Events
###############################################################################


@dataclass(
    slots=True
)
class WorkflowStartedEvent(RuntimeEvent):
    """
    Emitted when workflow execution starts.
    """

    workflow_id: UUID
    target: str
    profile: str


@dataclass(
    slots=True
)
class WorkflowFinishedEvent(RuntimeEvent):
    """
    Emitted when workflow execution finishes.
    """

    workflow_id: UUID
    success: bool


###############################################################################
# Stage Events
###############################################################################


@dataclass(
    slots=True
)
class StageStartedEvent(RuntimeEvent):
    """
    Emitted when a pipeline stage starts.
    """

    stage: int
    name: str


@dataclass(
    slots=True
)
class StageFinishedEvent(RuntimeEvent):
    """
    Emitted when a pipeline stage completes.
    """

    stage: int
    name: str
    success: bool


###############################################################################
# Tool Events
###############################################################################


@dataclass(
    slots=True
)
class ToolStartedEvent(RuntimeEvent):
    """
    Emitted when a tool starts execution.
    """

    tool: str
    capability: str


@dataclass(
    slots=True
)
class ToolFinishedEvent(RuntimeEvent):
    """
    Emitted when a tool finishes execution.
    """

    tool: str
    success: bool
    duration: float


###############################################################################
# Diagnostic Events
###############################################################################


@dataclass(
    slots=True
)
class WarningEvent(RuntimeEvent):
    """
    Runtime warning event.
    """

    message: str


@dataclass(
    slots=True
)
class ErrorEvent(RuntimeEvent):
    """
    Runtime error event.
    """

    message: str


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "RuntimeEvent",
    "WorkflowStartedEvent",
    "WorkflowFinishedEvent",
    "StageStartedEvent",
    "StageFinishedEvent",
    "ToolStartedEvent",
    "ToolFinishedEvent",
    "WarningEvent",
    "ErrorEvent",
]
