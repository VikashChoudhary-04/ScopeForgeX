"""
ScopeForgeX — Execution Result Model
====================================

Canonical result object returned by executable ScopeForgeX tools.

The model provides:

- Success/failure state
- stdout/stderr capture
- Artifacts
- Findings
- Warnings
- Errors
- Execution metadata
- Timing information
- Serialization helpers

v1.1.0
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
    Return the current UTC timestamp.
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
    Standard result returned by every ScopeForgeX executable tool.
    """

    # Identity
    tool: str
    capability: str

    # Execution state
    success: bool = False

    # Captured process output
    stdout: str = ""
    stderr: str = ""

    # Structured execution data
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

    # Timing
    started_at: datetime = field(
        default_factory=utc_now,
    )

    finished_at: datetime = field(
        default_factory=utc_now,
    )

    duration: float = 0.0

    ###########################################################################
    # Runtime Properties
    ###########################################################################

    @property
    def status(
        self,
    ) -> str:
        """
        Return a human-readable execution status.
        """

        if self.metadata.get(
            "status"
        ) == "skipped":

            return "skipped"

        if self.success:
            return "success"

        return "failed"

    ###########################################################################
    # Mutation Helpers
    ###########################################################################

    def add_artifact(
        self,
        artifact: str,
    ) -> None:
        """
        Add an artifact path if it is not already present.
        """

        if not artifact:
            return

        if artifact not in self.artifacts:
            self.artifacts.append(
                artifact
            )

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Add an execution error.
        """

        if not error:
            return

        self.errors.append(
            str(error)
        )

    def add_warning(
        self,
        warning: str,
    ) -> None:
        """
        Add an execution warning.
        """

        if not warning:
            return

        self.warnings.append(
            str(warning)
        )

    def add_finding(
        self,
        finding: Any,
    ) -> None:
        """
        Add a structured finding.
        """

        if finding is None:
            return

        self.findings.append(
            finding
        )

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
        stdout: str = "",
        stderr: str = "",
    ) -> "ExecutionResult":
        """
        Create a successful execution result.
        """

        now = utc_now()

        result = cls(
            tool=tool,
            capability=capability,
            success=True,
            stdout=stdout or "",
            stderr=stderr or "",
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
            duration=0.0,
        )

        return result

    @classmethod
    def failure(
        cls,
        tool: str,
        capability: str,
        error: str,
        artifacts=None,
        metadata=None,
        stdout: str = "",
        stderr: str = "",
    ) -> "ExecutionResult":
        """
        Create a failed execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            stdout=stdout or "",
            stderr=stderr or "",
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
            duration=0.0,
        )

    @classmethod
    def skipped(
        cls,
        tool: str,
        capability: str,
        reason: str,
    ) -> "ExecutionResult":
        """
        Create a skipped execution result.
        """

        now = utc_now()

        return cls(
            tool=tool,
            capability=capability,
            success=False,
            stdout="",
            stderr="",
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
            duration=0.0,
        )

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Convert the result into a JSON-compatible dictionary.
        """

        return {
            "tool": self.tool,
            "capability": self.capability,
            "success": self.success,
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "artifacts": list(
                self.artifacts
            ),
            "findings": list(
                self.findings
            ),
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration": self.duration,
        }
