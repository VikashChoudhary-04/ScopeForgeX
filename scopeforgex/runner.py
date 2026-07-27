"""
ScopeForgeX Command Runner
==========================

Shared command execution framework.

Features
--------
* Centralized process execution
* Consistent logging
* Safe output handling
* Timeout support
* Structured execution results
* Backward-compatible run_cmd() API

v0.5.0
"""

from __future__ import annotations

import subprocess
import time

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Mapping

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.ui import info
from scopeforgex.ui import warn


###############################################################################
# Defaults
###############################################################################

DEFAULT_TIMEOUT = 900


###############################################################################
# Execution Metadata
###############################################################################


@dataclass(slots=True)
class CommandExecution:
    """
    Internal execution metadata.
    """

    command: str
    timeout: int
    outfile: Path | None = None
    cwd: Path | None = None
    environment: Mapping[str, str] | None = None


###############################################################################
# Helper Functions
###############################################################################


def _prepare_output(
    outfile: str | None,
) -> Path | None:
    """
    Create the output file and its parent directory if required.
    """

    if outfile is None:
        return None

    output = Path(outfile)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    return output


def _append_log(
    outfile: Path | None,
    message: str,
) -> None:
    """
    Append a message to the output log.
    """

    if outfile is None:
        return

    with outfile.open(
        "a",
        encoding="utf-8",
    ) as stream:

        stream.write("\n")
        stream.write(message.rstrip())
        stream.write("\n")


def _build_run_kwargs(
    execution: CommandExecution,
) -> dict[str, Any]:
    """
    Build subprocess keyword arguments.
    """

    return {
        "shell": True,
        "text": True,
        "check": False,
        "timeout": execution.timeout,
        "cwd": execution.cwd,
        "env": execution.environment,
    }


def _execute(
    execution: CommandExecution,
) -> subprocess.CompletedProcess:
    """
    Execute a shell command.
    """

    info(
        f"Running: {execution.command}"
    )

    kwargs = _build_run_kwargs(
        execution,
    )

    if execution.outfile is not None:

        with execution.outfile.open(
            "w",
            encoding="utf-8",
        ) as stream:

            kwargs["stdout"] = stream
            kwargs["stderr"] = subprocess.STDOUT

            return subprocess.run(
                execution.command,
                **kwargs,
            )

    return subprocess.run(
        execution.command,
        **kwargs,
    )


###############################################################################
# Structured Command Execution
###############################################################################


def run_command(
    *,
    tool: str,
    capability: str,
    cmd: str,
    outfile: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> ExecutionResult:
    """
    Execute a command and return a structured ExecutionResult.

    This is the preferred API for new ScopeForgeX tools.

    Existing tools should continue using run_cmd() until migrated.
    """

    started = datetime.now()
    start_time = time.time()

    output_file = _prepare_output(
        outfile,
    )

    execution = CommandExecution(
        command=cmd,
        timeout=timeout,
        outfile=output_file,
    )

    artifacts: list[str] = []

    if output_file:
        artifacts.append(
            str(output_file)
        )

    try:

        result = _execute(
            execution,
        )

        finished = datetime.now()

        duration = (
            time.time()
            - start_time
        )

        if result.returncode != 0:

            return ExecutionResult.failure(
                tool=tool,
                capability=capability,
                error=(
                    f"Command exited with code "
                    f"{result.returncode}"
                ),
                artifacts=artifacts,
            )

        structured = ExecutionResult.success_result(
            tool=tool,
            capability=capability,
            artifacts=artifacts,
        )

        structured.started_at = started
        structured.finished_at = finished
        structured.duration = duration
        structured.exit_code = result.returncode

        return structured

    except subprocess.TimeoutExpired:

        finished = datetime.now()

        structured = ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=(
                f"Timeout reached "
                f"({timeout}s). "
                "Command terminated."
            ),
            artifacts=artifacts,
        )

        structured.started_at = started
        structured.finished_at = finished
        structured.duration = (
            time.time()
            - start_time
        )

        return structured

    except FileNotFoundError as exc:

        return ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=f"Executable not found: {exc}",
            artifacts=artifacts,
        )

    except KeyboardInterrupt:

        raise

    except Exception as exc:

        return ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=f"Command failed: {exc}",
            artifacts=artifacts,
        )


###############################################################################
# Legacy Public API
###############################################################################


def run_cmd(
    cmd: str,
    outfile: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> subprocess.CompletedProcess | None:
    """
    Execute a shell command.

    Legacy API preserved for existing tools.
    """

    execution = CommandExecution(
        command=cmd,
        timeout=timeout,
        outfile=_prepare_output(
            outfile,
        ),
    )

    try:

        result = _execute(
            execution,
        )

        if result.returncode != 0:

            warn(
                f"Command exited with code "
                f"{result.returncode}"
            )

            _append_log(
                execution.outfile,
                (
                    "[ScopeForgeX] "
                    f"Exit code: {result.returncode}"
                ),
            )

        return result

    except subprocess.TimeoutExpired:

        warn(
            f"Timeout reached "
            f"({execution.timeout}s). "
            "Command terminated."
        )

        _append_log(
            execution.outfile,
            (
                "[ScopeForgeX] "
                f"Timeout reached "
                f"({execution.timeout}s). "
                "Command terminated."
            ),
        )

        return None

    except FileNotFoundError as exc:

        warn(
            f"Executable not found: {exc}"
        )

        _append_log(
            execution.outfile,
            (
                "[ScopeForgeX] "
                f"Executable not found: {exc}"
            ),
        )

        return None

    except KeyboardInterrupt:

        warn(
            "Execution interrupted by user."
        )

        _append_log(
            execution.outfile,
            (
                "[ScopeForgeX] "
                "Execution interrupted "
                "by user."
            ),
        )

        raise

    except Exception as exc:

        warn(
            f"Command failed: {exc}"
        )

        _append_log(
            execution.outfile,
            (
                "[ScopeForgeX] "
                f"ERROR: {exc}"
            ),
        )

        return None


###############################################################################
# Convenience Helpers
###############################################################################


def run_cmd_success(
    cmd: str,
    outfile: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """
    Execute a command and return whether it completed successfully.
    """

    result = run_cmd(
        cmd=cmd,
        outfile=outfile,
        timeout=timeout,
    )

    return (
        result is not None
        and result.returncode == 0
    )


###############################################################################
# Public Exports
###############################################################################

__all__ = [
    "DEFAULT_TIMEOUT",
    "CommandExecution",
    "run_command",
    "run_cmd",
    "run_cmd_success",
]
