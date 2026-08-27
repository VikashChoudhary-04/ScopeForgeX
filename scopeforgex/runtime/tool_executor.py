"""
ScopeForgeX Tool Execution Layer
================================

Canonical execution layer for ScopeForgeX tool adapters.

The execution layer is responsible for:

- starting tool execution
- measuring execution duration
- applying execution context
- capturing execution status
- handling unexpected adapter failures
- recording results in RuntimeState
- preserving tool-generated artifacts
- maintaining a consistent execution contract

Architecture
------------

Workflow
    ↓
Tool Selection
    ↓
Tool Registry
    ↓
Tool Executor
    ↓
Tool Adapter
    ↓
ExecutionResult
    ↓
RuntimeState

Important
---------
The executor does NOT construct tool-specific commands.

Command construction remains the responsibility of each tool adapter.

The executor also avoids importing the registry at module import time.
This prevents the circular dependency:

    registry
        ↓
    tool_base
        ↓
    runtime
        ↓
    tool_executor
        ↓
    registry

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Any, Mapping


###############################################################################
# Execution Record
###############################################################################


@dataclass(frozen=True, slots=True)
class ToolExecutionRecord:
    """
    Immutable summary of one tool execution.
    """

    tool: str

    capability: str

    status: str

    started_at: float

    finished_at: float

    duration: float

    success: bool

    exit_code: int | None = None

    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the execution record.
        """

        return {
            "tool": self.tool,
            "capability": self.capability,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "success": self.success,
            "exit_code": self.exit_code,
            "error": self.error,
        }


###############################################################################
# Tool Executor
###############################################################################


class ToolExecutor:
    """
    Canonical ScopeForgeX tool execution coordinator.

    ToolExecutor deliberately knows nothing about individual tools.

    It receives a tool adapter from the registry and delegates execution
    to that adapter.
    """

    def __init__(
        self,
        runtime_state: Any | None = None,
        *,
        default_timeout: int = 600,
    ) -> None:
        """
        Initialize the execution layer.

        Args:
            runtime_state:
                Optional RuntimeState instance used to record execution.

            default_timeout:
                Default execution timeout exposed to adapters through ctx.
        """

        if default_timeout <= 0:
            raise ValueError(
                "default_timeout must be greater than zero."
            )

        self.runtime_state = runtime_state

        self.default_timeout = (
            default_timeout
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tool_name(
        adapter: Any,
    ) -> str:
        """
        Resolve the canonical tool name.
        """

        return str(
            getattr(
                adapter,
                "name",
                adapter.__class__.__name__,
            )
        ).strip().lower()

    @staticmethod
    def _capability(
        adapter: Any,
    ) -> str:
        """
        Resolve the canonical capability name.
        """

        return str(
            getattr(
                adapter,
                "capability",
                "unknown",
            )
        )

    @staticmethod
    def _status(
        result: Any,
    ) -> str:
        """
        Resolve an execution result status.

        Existing ExecutionResult implementations may expose status as
        either a string or an enum-like object.
        """

        value = getattr(
            result,
            "status",
            None,
        )

        if value is None:
            return (
                "success"
                if bool(
                    getattr(
                        result,
                        "success",
                        False,
                    )
                )
                else "failed"
            )

        return str(
            getattr(
                value,
                "value",
                value,
            )
        )

    @staticmethod
    def _exit_code(
        result: Any,
    ) -> int | None:
        """
        Resolve an optional process exit code.
        """

        value = getattr(
            result,
            "exit_code",
            None,
        )

        if value is None:
            return None

        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _error(
        result: Any,
    ) -> str | None:
        """
        Resolve an optional execution error.
        """

        value = getattr(
            result,
            "error",
            None,
        )

        if value is None:
            return None

        return str(
            value
        )

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    def _prepare_context(
        self,
        adapter: Any,
        ctx: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Prepare an isolated execution context.

        The executor never mutates the caller's original dictionary.
        """

        context = dict(
            ctx or {}
        )

        tool_name = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        context.setdefault(
            "tool",
            tool_name,
        )

        context.setdefault(
            "capability",
            capability,
        )

        context.setdefault(
            "timeout",
            self.default_timeout,
        )

        context.setdefault(
            "tool_timeout",
            self.default_timeout,
        )

        return context

    # ------------------------------------------------------------------
    # Runtime State
    # ------------------------------------------------------------------

    def _record_result(
        self,
        result: Any,
    ) -> None:
        """
        Record an ExecutionResult in RuntimeState when available.

        RuntimeState is intentionally treated through its public API rather
        than through direct mutation.
        """

        if self.runtime_state is None:
            return

        add_tool_result = getattr(
            self.runtime_state,
            "add_tool_result",
            None,
        )

        if callable(
            add_tool_result
        ):
            add_tool_result(
                result
            )

    # ------------------------------------------------------------------
    # Result Metadata
    # ------------------------------------------------------------------

    @staticmethod
    def _add_execution_metadata(
        result: Any,
        *,
        tool: str,
        capability: str,
        started_at: float,
        finished_at: float,
        duration: float,
    ) -> None:
        """
        Add standardized execution metadata when supported by the result.
        """

        metadata = getattr(
            result,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):
            return

        metadata.update(
            {
                "execution": {
                    "tool": tool,
                    "capability": capability,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "duration": duration,
                    "status": ToolExecutor._status(
                        result
                    ),
                    "success": bool(
                        getattr(
                            result,
                            "success",
                            False,
                        )
                    ),
                    "exit_code": ToolExecutor._exit_code(
                        result
                    ),
                }
            }
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        adapter: Any,
        ctx: Mapping[str, Any] | None = None,
    ) -> Any:
        """
        Execute one ScopeForgeX tool adapter.

        Args:
            adapter:
                Registered ScopeForgeX tool adapter.

            ctx:
                Shared workflow execution context.

        Returns:
            ExecutionResult returned by the adapter.

        Raises:
            TypeError:
                If the adapter does not expose a callable run() method.

        Unexpected adapter exceptions are converted into an ExecutionResult
        failure so one broken tool does not crash the complete assessment.
        """

        if not callable(
            getattr(
                adapter,
                "run",
                None,
            )
        ):
            raise TypeError(
                "Tool adapter must expose a callable run(ctx) method."
            )

        tool = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        context = self._prepare_context(
            adapter,
            ctx,
        )

        started_at = monotonic()

        try:
            result = adapter.run(
                context
            )

        except Exception as exc:
            finished_at = monotonic()

            duration = (
                finished_at
                - started_at
            )

            result = self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Unhandled tool adapter exception: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

            self._add_execution_metadata(
                result,
                tool=tool,
                capability=capability,
                started_at=started_at,
                finished_at=finished_at,
                duration=duration,
            )

            self._record_result(
                result
            )

            return result

        finished_at = monotonic()

        duration = (
            finished_at
            - started_at
        )

        self._add_execution_metadata(
            result,
            tool=tool,
            capability=capability,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
        )

        self._record_result(
            result
        )

        return result

    # ------------------------------------------------------------------
    # Batch Execution
    # ------------------------------------------------------------------

    def execute_many(
        self,
        adapters: list[Any] | tuple[Any, ...],
        ctx: Mapping[str, Any] | None = None,
    ) -> list[Any]:
        """
        Execute multiple tool adapters sequentially.

        Execution order is preserved.

        Individual adapter failures are represented by their
        ExecutionResult and do not automatically abort the complete batch.
        """

        results: list[Any] = []

        for adapter in adapters:
            result = self.execute(
                adapter,
                ctx,
            )

            results.append(
                result
            )

        return results

    # ------------------------------------------------------------------
    # Failure Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _failure_result(
        *,
        tool: str,
        capability: str,
        error: str,
    ) -> Any:
        """
        Construct an ExecutionResult failure without importing the runtime
        package at module import time.
        """

        from scopeforgex.models.execution_result import (
            ExecutionResult,
        )

        return ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=error,
        )


###############################################################################
# Convenience Function
###############################################################################


def execute_tool(
    adapter: Any,
    ctx: Mapping[str, Any] | None = None,
    *,
    runtime_state: Any | None = None,
    timeout: int = 600,
) -> Any:
    """
    Execute one tool through the canonical ToolExecutor.
    """

    executor = ToolExecutor(
        runtime_state=runtime_state,
        default_timeout=timeout,
    )

    return executor.execute(
        adapter,
        ctx,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "ToolExecutionRecord",
    "ToolExecutor",
    "execute_tool",
]
