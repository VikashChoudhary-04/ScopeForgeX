"""
ScopeForgeX Runtime Events
==========================

Defines runtime events emitted during workflow execution.

Events provide an audit trail for:
- workflow lifecycle
- stage execution
- tool execution
- artifact tracking
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


@dataclass(slots=True)
class RuntimeEvent:
    """
    Base runtime event.

    Keyword-only defaults prevent dataclass inheritance ordering conflicts.
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


@dataclass(slots=True)
class WorkflowStartedEvent(RuntimeEvent):

    workflow_id: UUID
    target: str
    profile: str


@dataclass(slots=True)
class WorkflowFinishedEvent(RuntimeEvent):

    workflow_id: UUID
    success: bool


###############################################################################
# Stage Events
###############################################################################


@dataclass(slots=True)
class StageStartedEvent(RuntimeEvent):

    stage: int
    name: str


@dataclass(slots=True)
class StageFinishedEvent(RuntimeEvent):

    stage: int
    name: str
    success: bool


###############################################################################
# Tool Events
###############################################################################


@dataclass(slots=True)
class ToolStartedEvent(RuntimeEvent):

    tool: str
    capability: str


@dataclass(slots=True)
class ToolFinishedEvent(RuntimeEvent):

    tool: str
    success: bool
    duration: float


###############################################################################
# Artifact Events
###############################################################################


@dataclass(slots=True)
class ArtifactCreatedEvent(RuntimeEvent):
    """
    Emitted when a new artifact is produced.
    """

    path: str
    artifact_type: str = "file"


@dataclass(slots=True)
class ArtifactRemovedEvent(RuntimeEvent):
    """
    Emitted when an artifact is removed.
    """

    path: str


###############################################################################
# Diagnostic Events
###############################################################################


@dataclass(slots=True)
class WarningEvent(RuntimeEvent):

    message: str


@dataclass(slots=True)
class ErrorEvent(RuntimeEvent):

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
    "ArtifactCreatedEvent",
    "ArtifactRemovedEvent",
    "WarningEvent",
    "ErrorEvent",
]
