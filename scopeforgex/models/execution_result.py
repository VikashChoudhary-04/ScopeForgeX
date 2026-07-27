"""
ScopeForgeX Execution Result Model
===================================

Canonical execution result object used by all tools.

v0.5.1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


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
# Execution Result
###############################################################################


@dataclass(slots=True)
class ExecutionResult:
    """
    Standard result returned by every ScopeForgeX tool.
    """

    tool: str

    capability: str

    success: bool

    artifacts: list[str] = field(
        default_factory=list,
    )

    findings: list[Any] = field(
        default_factory=list,
    )

    warnings: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    started_at: datetime = field(
        default_factory=utc_now,
    )

    finished_at: datetime = field(
        default_factory=utc_now,
    )


    ###########################################################################
    # Runtime Compatibility Properties
    ###########################################################################


    @property
    def duration(
        self,
    ) -> float:
        """
        Return execution duration in seconds.

        Compatible with workflow runtime tracking.
        """

        return (
            self.finished_at.timestamp()
            -
            self.started_at.timestamp()
        )


    @property
    def status(
        self,
    ) -> str:
        """
        Return human-readable execution status.
        """

        if self.metadata.get(
            "status"
        ) == "skipped":

            return "skipped"

        if self.success:

            return "success"

        return "failed"


    ###########################################################################
    # Constructors
    ###########################################################################


    @classmethod
    def success_result(
        cls,
        tool: str,
        capability: str,
        artifacts=None,
        findings=None,
        metadata=None,
        warnings=None,
    ) -> "ExecutionResult":
        """
        Create successful execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=True,
            artifacts=list(
                artifacts or []
            ),
            findings=list(
                findings or []
            ),
            warnings=list(
                warnings or []
            ),
            errors=[],
            metadata=metadata or {},
            started_at=now,
            finished_at=utc_now(),
        )


    @classmethod
    def failure(
        cls,
        tool: str,
        capability: str,
        error: str,
        artifacts=None,
        metadata=None,
    ) -> "ExecutionResult":
        """
        Create failed execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            artifacts=list(
                artifacts or []
            ),
            findings=[],
            warnings=[],
            errors=[
                error
            ],
            metadata=metadata or {},
            started_at=now,
            finished_at=utc_now(),
        )


    @classmethod
    def skipped(
        cls,
        tool: str,
        capability: str,
        reason: str,
    ) -> "ExecutionResult":
        """
        Create skipped execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            artifacts=[],
            findings=[],
            warnings=[
                reason
            ],
            errors=[],
            metadata={
                "status": "skipped",
            },
            started_at=now,
            finished_at=utc_now(),
        )


    ###########################################################################
    # Serialization
    ###########################################################################


    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Convert result to dictionary.
        """

        return {
            "tool": self.tool,
            "capability": self.capability,
            "success": self.success,
            "status": self.status,
            "duration": self.duration,
            "artifacts": self.artifacts,
            "findings": self.findings,
            "warnings": self.warnings,
            "errors": self.errors,
            "metadata": self.metadata,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
        }


###############################################################################
# Public API
###############################################################################


__all__ = [
    "ExecutionResult",
]
