"""
scopeforgex.models.tool_result

Standard execution result returned by every ScopeForgeX capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ToolResult:
    """
    Canonical execution result for a ScopeForgeX capability.

    Every tool should return exactly one ToolResult instance.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    tool: str
    capability: str

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    success: bool

    started_at: datetime
    finished_at: datetime

    duration: float

    exit_code: int | None = None

    # ------------------------------------------------------------------
    # Outputs
    # ------------------------------------------------------------------

    artifacts: list[Path] = field(default_factory=list)

    findings: list[Any] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    warnings: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience Properties
    # ------------------------------------------------------------------

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)


__all__ = ["ToolResult"]
