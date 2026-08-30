"""
ScopeForgeX Tool Execution Layer
================================

Canonical execution layer for ScopeForgeX tool adapters.

Responsibilities:

- Execute new-style ToolAdapter commands
- Preserve legacy ToolBase compatibility during migration
- Measure execution duration
- Apply execution context
- Capture execution status
- Convert unexpected adapter failures into ExecutionResult failures
- Invoke adapter result collection hooks after process execution
- Record results in RuntimeState
- Preserve tool-generated artifacts
- Maintain a consistent execution contract

Architecture
------------

Workflow
    ↓
Tool Registry
    ↓
Tool Adapter
    ↓
Tool Executor
    ↓
Command Execution
    ↓
ExecutionResult
    ↓
Adapter Collection
    ↓
RuntimeState

New-style adapters own command construction and post-execution collection.

ToolExecutor owns process execution.

Legacy ToolBase adapters may continue to expose run(ctx) until migration
is complete.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from dataclasses import dataclass
from time import monotonic
from typing import Any, Mapping

from scopeforgex.models.execution_result import ExecutionResult


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

    ToolExecutor coordinates execution but does not construct
    tool-specific arguments.

    New-style ToolAdapter instances expose build_command() and are
    executed through the canonical command runner.

    After command execution, an optional adapter collect(result) hook is
    invoked so adapters can preserve artifacts and perform tool-specific
    result collection without owning subprocess execution.

    Legacy ToolBase instances may still expose run(ctx) and are
    temporarily supported through the compatibility path.
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
                Default command timeout exposed to adapters through ctx.
        """

        if (
            not isinstance(
                default_timeout,
                int,
            )
            or isinstance(
                default_timeout,
                bool,
            )
        ):
            raise TypeError(
                "default_timeout must be an integer."
            )

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

        capability = getattr(
            adapter,
            "capability",
            None,
        )

        if capability is None:
            return "unknown"

        return str(
            getattr(
                capability,
                "value",
                capability,
            )
        )

    @staticmethod
    def _status(
        result: Any,
    ) -> str:
        """
        Resolve an execution result status.
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

    @staticmethod
    def _is_new_adapter(
        adapter: Any,
    ) -> bool:
        """
        Return True when the adapter exposes the new ToolAdapter command
        construction contract.
        """

        return callable(
            getattr(
                adapter,
                "build_command",
                None,
            )
        ) and callable(
            getattr(
                adapter,
                "build_arguments",
                None,
            )
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

        The executor never mutates the caller's original mapping.
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

        RuntimeState is intentionally accessed through its public API.
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
        result: ExecutionResult,
        *,
        tool: str,
        capability: str,
        started_at: float,
        finished_at: float,
        duration: float,
    ) -> None:
        """
        Add standardized execution metadata.
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
                    "error": ToolExecutor._error(
                        result
                    ),
                }
            }
        )

    # ------------------------------------------------------------------
    # Adapter Collection
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_result(
        adapter: Any,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Invoke an optional adapter-side result collection hook.

        The hook executes after process completion and therefore may:

        - preserve raw output artifacts
        - copy or transform generated files
        - invoke a dedicated collector
        - attach collection metadata
        - add collection warnings

        The hook must not become a second subprocess execution path.

        If the adapter returns an ExecutionResult, that result replaces the
        original result. Returning None or another value leaves the original
        result unchanged.
        """

        collect = getattr(
            adapter,
            "collect",
            None,
        )

        if not callable(
            collect
        ):
            return result

        try:
            collected = collect(
                result
            )

        except Exception as exc:
            result.add_warning(
                (
                    "Tool result collection failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

            return result

        if isinstance(
            collected,
            ExecutionResult,
        ):
            return collected

        return result

    # ------------------------------------------------------------------
    # Canonical Command Execution
    # ------------------------------------------------------------------

    def _execute_command(
        self,
        adapter: Any,
        context: dict[str, Any],
    ) -> ExecutionResult:
        """
        Build and execute a new-style adapter command.

        Tool-specific command construction remains entirely inside
        the adapter.
        """

        tool = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        try:
            command = adapter.build_command()

        except Exception as exc:
            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool command construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        if not isinstance(
            command,
            (list, tuple),
        ):
            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool adapter build_command() must return "
                    "a list or tuple of command arguments."
                ),
            )

        command = [
            str(argument)
            for argument in command
        ]

        if not command:
            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool adapter produced an empty command."
                ),
            )

        return self._run_process(
            tool=tool,
            capability=capability,
            command=command,
            context=context,
        )

    # ------------------------------------------------------------------
    # Process Execution
    # ------------------------------------------------------------------

    @staticmethod
    def _run_process(
        *,
        tool: str,
        capability: str,
        command: list[str],
        context: Mapping[str, Any],
    ) -> ExecutionResult:
        """
        Execute a fully constructed command.

        This method delegates process execution to the existing command
        runner while keeping the public execution contract centralized.
        """

        from scopeforgex.runner import run_command

        timeout = context.get(
            "tool_timeout",
            context.get(
                "timeout",
                600,
            ),
        )

        outfile = context.get(
            "outfile"
        )

        cwd = context.get(
            "cwd"
        )

        env = context.get(
            "env"
        )

        command_text = _command_to_string(
            command
        )

        return run_command(
            tool=tool,
            capability=capability,
            cmd=command_text,
            outfile=(
                str(outfile)
                if outfile is not None
                else None
            ),
            timeout=int(
                timeout
            ),
            cwd=(
                str(cwd)
                if cwd is not None
                else None
            ),
            env=(
                dict(env)
                if isinstance(
                    env,
                    Mapping,
                )
                else None
            ),
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        adapter: Any,
        ctx: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """
        Execute one ScopeForgeX tool adapter.

        New-style ToolAdapter instances use build_command() and the
        canonical command execution path.

        After successful or failed process execution, an optional adapter
        collect(result) hook is invoked to preserve artifacts and perform
        tool-specific result collection.

        Legacy adapters continue to use run(ctx) until migrated.

        Unexpected adapter exceptions are converted into an
        ExecutionResult failure.
        """

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
            if self._is_new_adapter(
                adapter
            ):
                result = self._execute_command(
                    adapter,
                    context,
                )

                result = self._collect_result(
                    adapter,
                    result,
                )

            else:
                run = getattr(
                    adapter,
                    "run",
                    None,
                )

                if not callable(
                    run
                ):
                    raise TypeError(
                        "Tool adapter must expose either "
                        "build_command() or run(ctx)."
                    )

                result = run(
                    context
                )

        except KeyboardInterrupt:
            raise

        except Exception as exc:
            result = self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Unhandled tool adapter exception: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        finished_at = monotonic()

        duration = (
            finished_at
            - started_at
        )

        if isinstance(
            result,
            ExecutionResult,
        ):
            result.duration = (
                duration
                if result.duration <= 0
                else result.duration
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
    ) -> list[ExecutionResult]:
        """
        Execute multiple tool adapters sequentially.

        Execution order is preserved.

        Individual adapter failures are represented by their
        ExecutionResult and do not automatically abort the batch.
        """

        results: list[ExecutionResult] = []

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
    ) -> ExecutionResult:
        """
        Construct a canonical ExecutionResult failure.
        """

        return ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=error,
        )


###############################################################################
# Command Formatting
###############################################################################


def _command_to_string(
    command: list[str],
) -> str:
    """
    Convert a structured command into a safely quoted shell command.
    """

    import shlex

    return shlex.join(
        command
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
) -> ExecutionResult:
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
