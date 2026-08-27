"""
ScopeForgeX Runtime Results
===========================

Canonical result models used by the ScopeForgeX runtime.

The runtime separates:

    Tool execution
        ↓
    Stage result
        ↓
    Workflow result

Tool-level execution details are represented by ExecutionResult.

StageResult aggregates the execution results produced during one assessment
phase.

WorkflowResult aggregates the complete assessment execution and provides the
final workflow-level status.

v1.1.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.runtime.enums import (
    AssessmentPhase,
    ExecutionStatus,
)


###############################################################################
# Stage Result
###############################################################################


@dataclass
class StageResult:
    """
    Aggregate result for one ScopeForgeX assessment stage.

    A stage may execute multiple tools. Their individual ExecutionResult
    objects are preserved in ``tool_results`` rather than being flattened.
    """

    stage: str
    phase: AssessmentPhase | str | None = None

    status: ExecutionStatus = ExecutionStatus.PENDING

    tool_results: list[ExecutionResult] = field(
        default_factory=list,
    )

    started_at: datetime | None = None
    ended_at: datetime | None = None

    duration: float = 0.0

    findings: list[Any] = field(
        default_factory=list,
    )

    artifacts: list[Any] = field(
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

    ###########################################################################
    # Result State
    ###########################################################################

    @property
    def success(self) -> bool:
        """
        Return True when the stage completed successfully.
        """

        return self.status == ExecutionStatus.SUCCESS

    @property
    def failed(self) -> bool:
        """
        Return True when the stage failed.
        """

        return self.status == ExecutionStatus.FAILED

    @property
    def skipped(self) -> bool:
        """
        Return True when the stage was skipped.
        """

        return self.status == ExecutionStatus.SKIPPED

    ###########################################################################
    # Aggregation
    ###########################################################################

    @property
    def successful_tools(self) -> int:
        """
        Return the number of successful tool executions.
        """

        return sum(
            1
            for result in self.tool_results
            if result.status == ExecutionStatus.SUCCESS
        )

    @property
    def failed_tools(self) -> int:
        """
        Return the number of failed tool executions.
        """

        return sum(
            1
            for result in self.tool_results
            if result.status == ExecutionStatus.FAILED
        )

    @property
    def skipped_tools(self) -> int:
        """
        Return the number of skipped tool executions.
        """

        return sum(
            1
            for result in self.tool_results
            if result.status == ExecutionStatus.SKIPPED
        )

    @property
    def tool_count(self) -> int:
        """
        Return the total number of tool executions.
        """

        return len(
            self.tool_results
        )

    def add_result(
        self,
        result: ExecutionResult,
    ) -> None:
        """
        Add an individual tool execution result to the stage.
        """

        self.tool_results.append(
            result
        )

        if getattr(
            result,
            "artifacts",
            None,
        ):
            self.artifacts.extend(
                result.artifacts
            )

        if getattr(
            result,
            "warnings",
            None,
        ):
            self.warnings.extend(
                result.warnings
            )

        if getattr(
            result,
            "errors",
            None,
        ):
            self.errors.extend(
                result.errors
            )

        result_findings = getattr(
            result,
            "findings",
            None,
        )

        if result_findings:
            self.findings.extend(
                result_findings
            )

    def finalize(
        self,
    ) -> "StageResult":
        """
        Derive the final stage status from its tool results.
        """

        if not self.tool_results:
            if self.status == ExecutionStatus.PENDING:
                self.status = ExecutionStatus.SKIPPED

            return self

        statuses = {
            result.status
            for result in self.tool_results
        }

        if ExecutionStatus.FAILED in statuses:
            self.status = ExecutionStatus.FAILED

        elif (
            statuses
            and statuses <= {
                ExecutionStatus.SKIPPED,
            }
        ):
            self.status = ExecutionStatus.SKIPPED

        elif ExecutionStatus.SUCCESS in statuses:
            self.status = ExecutionStatus.SUCCESS

        else:
            self.status = ExecutionStatus.FAILED

        if (
            self.started_at is not None
            and self.ended_at is not None
        ):
            self.duration = (
                self.ended_at
                - self.started_at
            ).total_seconds()

        return self

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a JSON-compatible representation of the stage result.
        """

        return {
            "stage": self.stage,
            "phase": (
                self.phase.value
                if isinstance(
                    self.phase,
                    AssessmentPhase,
                )
                else self.phase
            ),
            "status": (
                self.status.value
                if isinstance(
                    self.status,
                    ExecutionStatus,
                )
                else self.status
            ),
            "tool_results": [
                (
                    result.as_dict()
                    if hasattr(
                        result,
                        "as_dict",
                    )
                    else result
                )
                for result in self.tool_results
            ],
            "started_at": (
                self.started_at.isoformat()
                if self.started_at
                else None
            ),
            "ended_at": (
                self.ended_at.isoformat()
                if self.ended_at
                else None
            ),
            "duration": self.duration,
            "findings": self.findings,
            "artifacts": [
                str(artifact)
                for artifact in self.artifacts
            ],
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
            "successful_tools": (
                self.successful_tools
            ),
            "failed_tools": (
                self.failed_tools
            ),
            "skipped_tools": (
                self.skipped_tools
            ),
            "tool_count": self.tool_count,
        }


###############################################################################
# Workflow Result
###############################################################################


@dataclass
class WorkflowResult:
    """
    Aggregate result for a complete ScopeForgeX assessment.

    WorkflowResult preserves stage-level results while also providing
    assessment-wide statistics and metadata.
    """

    target: str

    profile: str = "standard"

    status: ExecutionStatus = ExecutionStatus.PENDING

    stage_results: list[StageResult] = field(
        default_factory=list,
    )

    started_at: datetime | None = None
    ended_at: datetime | None = None

    duration: float = 0.0

    findings: list[Any] = field(
        default_factory=list,
    )

    artifacts: list[Any] = field(
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

    ###########################################################################
    # Result State
    ###########################################################################

    @property
    def success(self) -> bool:
        """
        Return True when the workflow completed successfully.
        """

        return self.status == ExecutionStatus.SUCCESS

    @property
    def failed(self) -> bool:
        """
        Return True when the workflow failed.
        """

        return self.status == ExecutionStatus.FAILED

    @property
    def skipped(self) -> bool:
        """
        Return True when the workflow was skipped.
        """

        return self.status == ExecutionStatus.SKIPPED

    ###########################################################################
    # Stage Access
    ###########################################################################

    @property
    def successful_stages(self) -> int:
        """
        Return the number of successful stages.
        """

        return sum(
            1
            for stage in self.stage_results
            if stage.status == ExecutionStatus.SUCCESS
        )

    @property
    def failed_stages(self) -> int:
        """
        Return the number of failed stages.
        """

        return sum(
            1
            for stage in self.stage_results
            if stage.status == ExecutionStatus.FAILED
        )

    @property
    def skipped_stages(self) -> int:
        """
        Return the number of skipped stages.
        """

        return sum(
            1
            for stage in self.stage_results
            if stage.status == ExecutionStatus.SKIPPED
        )

    @property
    def stage_count(self) -> int:
        """
        Return the number of recorded stages.
        """

        return len(
            self.stage_results
        )

    def add_stage(
        self,
        result: StageResult,
    ) -> None:
        """
        Add a completed or in-progress stage result.
        """

        self.stage_results.append(
            result
        )

        self.findings.extend(
            result.findings
        )

        self.artifacts.extend(
            result.artifacts
        )

        self.warnings.extend(
            result.warnings
        )

        self.errors.extend(
            result.errors
        )

    ###########################################################################
    # Finalization
    ###########################################################################

    def finalize(
        self,
    ) -> "WorkflowResult":
        """
        Derive the final workflow status from its stage results.
        """

        if not self.stage_results:
            if self.status == ExecutionStatus.PENDING:
                self.status = ExecutionStatus.SKIPPED

            return self

        statuses = {
            stage.status
            for stage in self.stage_results
        }

        if ExecutionStatus.FAILED in statuses:
            self.status = ExecutionStatus.FAILED

        elif (
            statuses
            and statuses <= {
                ExecutionStatus.SKIPPED,
            }
        ):
            self.status = ExecutionStatus.SKIPPED

        elif ExecutionStatus.SUCCESS in statuses:
            self.status = ExecutionStatus.SUCCESS

        else:
            self.status = ExecutionStatus.FAILED

        if (
            self.started_at is not None
            and self.ended_at is not None
        ):
            self.duration = (
                self.ended_at
                - self.started_at
            ).total_seconds()

        return self

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a JSON-compatible representation of the workflow result.
        """

        return {
            "target": self.target,
            "profile": self.profile,
            "status": (
                self.status.value
                if isinstance(
                    self.status,
                    ExecutionStatus,
                )
                else self.status
            ),
            "stage_results": [
                stage.as_dict()
                for stage in self.stage_results
            ],
            "started_at": (
                self.started_at.isoformat()
                if self.started_at
                else None
            ),
            "ended_at": (
                self.ended_at.isoformat()
                if self.ended_at
                else None
            ),
            "duration": self.duration,
            "findings": self.findings,
            "artifacts": [
                str(artifact)
                for artifact in self.artifacts
            ],
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
            "successful_stages": (
                self.successful_stages
            ),
            "failed_stages": (
                self.failed_stages
            ),
            "skipped_stages": (
                self.skipped_stages
            ),
            "stage_count": self.stage_count,
        }


###############################################################################
# Public API
###############################################################################


__all__ = [
    "StageResult",
    "WorkflowResult",
]
