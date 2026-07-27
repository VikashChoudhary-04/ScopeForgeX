"""
ScopeForgeX Execution Result Model
==================================

Canonical execution result returned by ScopeForgeX capabilities.

Provides:
- Standard execution metadata
- Artifact tracking
- Finding tracking
- Warning/error collection
- Backward-compatible result constructors

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
    Canonical execution result for every ScopeForgeX capability.
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
    )

    findings: list[Any] = field(
        default_factory=list,
    )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    warnings: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    # ------------------------------------------------------------------
    # Convenience Properties
    # ------------------------------------------------------------------

    @property
    def successful(self) -> bool:
        """
        Compatibility alias.
        """

        return self.success


    @property
    def failed(self) -> bool:
        """
        Compatibility alias.
        """

        return not self.success


    @property
    def artifact_count(self) -> int:
        return len(
            self.artifacts
        )


    @property
    def finding_count(self) -> int:
        return len(
            self.findings
        )


    @property
    def has_warnings(self) -> bool:
        return bool(
            self.warnings
        )


    @property
    def has_errors(self) -> bool:
        return bool(
            self.errors
        )


    # ------------------------------------------------------------------
    # Backward Compatibility Constructors
    # ------------------------------------------------------------------

    @classmethod
    def success_result(
        cls,
        tool: str,
        capability: str = "",
        artifacts: list[Path] | None = None,
        findings: list[Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "ExecutionResult":
        """
        Create a successful execution result.

        Keeps existing tool implementations compatible
        with the v0.5.0 runtime model.
        """

        now = datetime.now()

        return cls(
            tool=tool,
            capability=capability,
            success=True,
            started_at=now,
            finished_at=now,
            duration=0.0,
            artifacts=artifacts or [],
            findings=findings or [],
            metadata=metadata or {},
        )


    @classmethod
    def failure_result(
        cls,
        tool: str,
        error: str,
        capability: str = "",
    ) -> "ExecutionResult":
        """
        Create a failed execution result.
        """

        now = datetime.now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            started_at=now,
            finished_at=now,
            duration=0.0,
            errors=[
                error,
            ],
        )


__all__ = [
    "ExecutionResult",
]
