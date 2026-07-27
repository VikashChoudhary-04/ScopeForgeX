"""
ScopeForgeX Runtime Package
===========================

Public runtime API for ScopeForgeX.

The runtime package provides the authoritative execution model used by the
Workflow Engine. It exposes strongly typed models for execution state,
statistics, artifacts, events and execution results.

Package Layout
--------------
runtime/
├── enums.py
├── events.py
├── artifacts.py
├── statistics.py
├── results.py
├── state.py
└── __init__.py

Design Principles
-----------------
- RuntimeState is the single source of truth.
- Structured execution data.
- Strong typing.
- Immutable execution models where appropriate.
- Filesystem-independent reporting.
"""

from .artifacts import Artifact
from .enums import (
    ArtifactType,
    EventType,
    Severity,
    StageType,
    Status,
    StrEnum,
    ToolCategory,
)
from .events import (
    ArtifactCreatedEvent,
    ErrorRecordedEvent,
    FindingRecordedEvent,
    RuntimeEvent,
    StageFinishedEvent,
    StageStartedEvent,
    ToolFinishedEvent,
    ToolStartedEvent,
    WarningRecordedEvent,
    WorkflowFinishedEvent,
    WorkflowStartedEvent,
)
from .results import (
    ExecutionResult,
    StageResult,
    ToolResult,
    WorkflowResult,
)
from .state import RuntimeState
from .statistics import WorkflowStatistics

__version__ = "1.0"

__all__ = [
    # Runtime
    "RuntimeState",

    # Statistics
    "WorkflowStatistics",

    # Artifacts
    "Artifact",

    # Results
    "ExecutionResult",
    "ToolResult",
    "StageResult",
    "WorkflowResult",

    # Events
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

    # Enums
    "Status",
    "Severity",
    "ArtifactType",
    "StageType",
    "ToolCategory",
    "EventType",
    "StrEnum",
]
