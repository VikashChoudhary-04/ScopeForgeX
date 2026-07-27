"""
ScopeForgeX Runtime Enums
=========================

Defines the core enumerations used throughout the ScopeForgeX runtime
execution engine.

These enums provide a strongly typed vocabulary for describing workflow
execution, tool status, severity levels, runtime events, execution stages,
and generated artifacts.

Design Principles
-----------------
- Human-readable string values.
- JSON serialization friendly.
- No project dependencies.
- Safe to import from anywhere.
- Stable public API.

This module intentionally contains no business logic.
"""

from __future__ import annotations

from enum import Enum

try:
    # Python 3.11+
    from enum import StrEnum
except ImportError:  # pragma: no cover
    class StrEnum(str, Enum):
        """Compatibility implementation for Python < 3.11."""
        pass


# ============================================================================
# Execution Status
# ============================================================================

class Status(StrEnum):
    """
    Represents the lifecycle state of an executable component.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


# ============================================================================
# Severity
# ============================================================================

class Severity(StrEnum):
    """
    Standardized severity levels.

    Intended for findings, warnings and runtime diagnostics.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# Artifact Types
# ============================================================================

class ArtifactType(StrEnum):
    """
    Types of artifacts produced during execution.
    """

    TEXT = "text"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"
    XML = "xml"
    LOG = "log"
    SCREENSHOT = "screenshot"
    PCAP = "pcap"
    OTHER = "other"


# ============================================================================
# Tool Categories
# ============================================================================

class ToolCategory(StrEnum):
    """
    High-level categorization of executors/tools.
    """

    RECON = "recon"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    UTILITY = "utility"


# ============================================================================
# Workflow Stages
# ============================================================================

class StageType(StrEnum):
    """
    Canonical workflow stages.

    These represent logical stages of the ScopeForgeX workflow,
    independent of the internal implementation.
    """

    RECON = "recon"
    ENUMERATION = "enumeration"
    VULNERABILITY = "vulnerability"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


# ============================================================================
# Runtime Events
# ============================================================================

class EventType(StrEnum):
    """
    Events emitted by the runtime event system.
    """

    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_FINISHED = "workflow_finished"

    STAGE_STARTED = "stage_started"
    STAGE_FINISHED = "stage_finished"

    TOOL_STARTED = "tool_started"
    TOOL_FINISHED = "tool_finished"

    ARTIFACT_CREATED = "artifact_created"

    FINDING_RECORDED = "finding_recorded"

    WARNING_RECORDED = "warning_recorded"

    ERROR_RECORDED = "error_recorded"


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "ArtifactType",
    "EventType",
    "Severity",
    "StageType",
    "Status",
    "StrEnum",
    "ToolCategory",
]
