"""
ScopeForgeX Execution Result Model
==================================

Canonical execution result returned by every ScopeForgeX capability.

Every tool, stage, and workflow component uses ExecutionResult as the
standard structured output model.

v0.5.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ExecutionResult:
    """
    Canonical execution result for a ScopeForgeX capability.

    Every executable capability should return exactly one ExecutionResult
    instance.

    Default collections are keyword-only to support inheritance by:
    - Tool results
    - Stage results
    - Workflow results
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

    artifacts: list[Path] = field(
        default_factory=list,
        kw_only=True,
    )

    findings: list[Any] = field(
        default_factory=list,
        kw_only=True,
    )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    warnings: list[str] = field(
        default_factory=list,
        kw_only=True,
    )

    errors: list[str] = field(
        default_factory=list,
        kw_only=True,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
        kw_only=True,
    )

    # ------------------------------------------------------------------
    # Convenience Properties
    # ------------------------------------------------------------------

    @property
    def artifact_count(
        self,
    ) -> int:
        return len(
            self.artifacts
        )

    @property
    def finding_count(
        self,
    ) -> int:
        return len(
            self.findings
        )

    @property
    def has_warnings(
        self,
    ) -> bool:
        return bool(
            self.warnings
        )

    @property
    def has_errors(
        self,
    ) -> bool:
        return bool(
            self.errors
        )


__all__ = [
    "ExecutionResult",
]
