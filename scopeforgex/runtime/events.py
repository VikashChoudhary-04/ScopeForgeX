"""
ScopeForgeX Runtime Events
==========================

Defines immutable runtime event models used throughout the ScopeForgeX
execution engine.

Every meaningful action performed during workflow execution is represented
as a structured RuntimeEvent. Events are emitted by the RuntimeState and
consumed by subscribers such as loggers, dashboards, progress bars,
reporters, or future remote execution services.

Design Principles
-----------------
- Immutable dataclasses.
- Strong typing.
- Standard-library only.
- UTC timestamps.
- UUID-based event identifiers.
- JSON serialization friendly.
- Thread-safe by design.

This module intentionally contains no publish/subscribe logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from .enums import EventType, Severity, StageType


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


# ============================================================================
# Base Event
# ============================================================================


@dataclass(frozen=True, slots=True)
class RuntimeEvent:
    """
    Base class for all runtime events.
    """

    event_type: EventType

    message: str

    workflow_id: str | None = None

    stage: StageType | None = None

    tool: str | None = None

    severity: Severity = Severity.INFO

    metadata: dict[str, Any] = field(default_factory=dict)

    timestamp: datetime = field(default_factory=utc_now)

    event_id: UUID = field(default_factory=uuid4)


# ============================================================================
# Workflow Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class WorkflowStartedEvent(RuntimeEvent):
    """Workflow execution started."""

    event_type: EventType = EventType.WORKFLOW_STARTED


@dataclass(frozen=True, slots=True)
class WorkflowFinishedEvent(RuntimeEvent):
    """Workflow execution finished."""

    event_type: EventType = EventType.WORKFLOW_FINISHED


# ============================================================================
# Stage Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class StageStartedEvent(RuntimeEvent):
    """Workflow stage started."""

    event_type: EventType = EventType.STAGE_STARTED


@dataclass(frozen=True, slots=True)
class StageFinishedEvent(RuntimeEvent):
    """Workflow stage finished."""

    event_type: EventType = EventType.STAGE_FINISHED


# ============================================================================
# Tool Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class ToolStartedEvent(RuntimeEvent):
    """Tool execution started."""

    event_type: EventType = EventType.TOOL_STARTED


@dataclass(frozen=True, slots=True)
class ToolFinishedEvent(RuntimeEvent):
    """Tool execution finished."""

    event_type: EventType = EventType.TOOL_FINISHED


# ============================================================================
# Artifact Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class ArtifactCreatedEvent(RuntimeEvent):
    """Artifact successfully created."""

    event_type: EventType = EventType.ARTIFACT_CREATED


# ============================================================================
# Finding Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class FindingRecordedEvent(RuntimeEvent):
    """Security finding recorded."""

    event_type: EventType = EventType.FINDING_RECORDED


# ============================================================================
# Warning Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class WarningRecordedEvent(RuntimeEvent):
    """Runtime warning recorded."""

    event_type: EventType = EventType.WARNING_RECORDED

    severity: Severity = Severity.MEDIUM


# ============================================================================
# Error Events
# ============================================================================


@dataclass(frozen=True, slots=True)
class ErrorRecordedEvent(RuntimeEvent):
    """Runtime error recorded."""

    event_type: EventType = EventType.ERROR_RECORDED

    severity: Severity = Severity.HIGH


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "RuntimeEvent",
    "WorkflowStartedEvent",
    "WorkflowFinishedEvent",
    "StageStartedEvent",
    "StageFinishedEvent",
    "ToolStartedEvent",
    "ToolFinishedEvent",
    "ArtifactCreatedEvent",
    "FindingRecordedEvent",
    "WarningRecordedEvent",
    "ErrorRecordedEvent",
    "utc_now",
]
