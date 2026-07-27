"""
ScopeForgeX Execution Result Model
=================================

Canonical execution result returned by every ScopeForgeX capability.

This model is intentionally independent from individual tools and stages.
It represents the outcome of a capability execution and will eventually
replace the legacy ToolResult used by ToolBase.

The execution engine (Runner) is expected to populate timing information.
Individual tools should focus on producing findings and artifacts.

v1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ExecutionResult:
    """
    Standard execution result produced by a ScopeForgeX capability.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    tool: str
    capability: str

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    success: bool = True

    # ------------------------------------------------------------------
    # Timing
    #
    # These fields are intended to be populated by the execution engine.
    # They are optional during the migration away from the legacy model.
    # ------------------------------------------------------------------

    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration: float | None = None

    exit_code: int | None = None

    # ------------------------------------------------------------------
    # Outputs
    # ------------------------------------------------------------------

    artifacts: list[Path] = field(default_factory=list)

    # Placeholder until Finding model is introduced.
    findings: list[Any] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    warnings: list[str] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Factory Constructors
    # ------------------------------------------------------------------

    @classmethod
    def success_result(
        cls,
        *,
        tool: str,
        capability: str,
        artifacts: list[str | Path] | None = None,
        findings: list[Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "ExecutionResult":

        return cls(
            tool=tool,
            capability=capability,
            success=True,
            artifacts=[Path(p) for p in (artifacts or [])],
            findings=findings or [],
            metadata=metadata or {},
        )

    @classmethod
    def failure(
        cls,
        *,
        tool: str,
        capability: str,
        error: str,
        artifacts: list[str | Path] | None = None,
    ) -> "ExecutionResult":

        result = cls(
            tool=tool,
            capability=capability,
            success=False,
            artifacts=[Path(p) for p in (artifacts or [])],
        )

        result.errors.append(error)

        return result

    @classmethod
    def skipped(
        cls,
        *,
        tool: str,
        capability: str,
        reason: str,
    ) -> "ExecutionResult":

        result = cls(
            tool=tool,
            capability=capability,
            success=False,
        )

        result.warnings.append(reason)

        return result

    # ------------------------------------------------------------------
    # Helper Methods
    # ------------------------------------------------------------------

    def add_artifact(self, artifact: str | Path) -> None:
        self.artifacts.append(Path(artifact))

    def add_finding(self, finding: Any) -> None:
        self.findings.append(finding)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    def add_error(self, error: str) -> None:
        self.errors.append(error)

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

    @property
    def completed(self) -> bool:
        return self.success and not self.has_errors

    @property
    def failed(self) -> bool:
        return not self.success

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the execution result into a JSON-friendly dictionary.
        """

        return {
            "tool": self.tool,
            "capability": self.capability,
            "success": self.success,
            "started_at": (
                self.started_at.isoformat()
                if self.started_at
                else None
            ),
            "finished_at": (
                self.finished_at.isoformat()
                if self.finished_at
                else None
            ),
            "duration": self.duration,
            "exit_code": self.exit_code,
            "artifacts": [str(p) for p in self.artifacts],
            "findings": self.findings,
            "warnings": self.warnings,
            "errors": self.errors,
            "metadata": self.metadata,
        }


__all__ = [
    "ExecutionResult",
]
