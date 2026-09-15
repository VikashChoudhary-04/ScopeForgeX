"""
ScopeForgeX — Command Runner
============================

Shared command execution wrapper used by executable ScopeForgeX tools.

Responsibilities:

- Execute external commands
- Capture stdout/stderr
- Persist combined execution logs
- Handle timeouts
- Handle missing executables
- Return canonical ExecutionResult objects
- Record execution metadata
- Resolve executables consistently from PATH

Tool adapters remain responsible for constructing their commands.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from scopeforgex.executable import resolve_executable
from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.ui import info, warn


###############################################################################
# Command Execution
###############################################################################


def run_command(
    *,
    tool: str,
    capability: str,
    cmd: str | list[str],
    outfile: str | None = None,
    timeout: int = 900,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> ExecutionResult:
    """
    Execute an external command and return a canonical ExecutionResult.

    Args:
        tool:
            Registered ScopeForgeX tool name.

        capability:
            Capability being exercised by the command.

        cmd:
            Fully constructed shell command as a string or argument list.

        outfile:
            Optional file receiving combined stdout/stderr.

        timeout:
            Maximum execution time in seconds.

        cwd:
            Optional working directory.

        env:
            Optional environment overrides.

    Returns:
        ExecutionResult describing the execution.
    """

    ###########################################################################
    # Timeout Validation
    ###########################################################################

    try:
        timeout_value = int(
            timeout
        )
    except (
        TypeError,
        ValueError,
    ):
        timeout_value = 900

    ###########################################################################
    # Command Validation
    ###########################################################################

    if isinstance(cmd, list):
        if not cmd:
            command = ""
            resolved_command: list[str] = []
        else:
            normalized_cmd = [
                str(argument)
                for argument in cmd
            ]

            if not normalized_cmd[0].strip():
                command = ""
                resolved_command = []
            else:
                command = shlex.join(
                    normalized_cmd
                )

                resolved_command = _resolve_argv(
                    normalized_cmd,
                    env=env,
                )

    else:
        command = str(cmd).strip()

        resolved_command = _resolve_command(
            command,
            env=env,
        )

    if not command:
        result = ExecutionResult(
            tool=tool,
            capability=capability,
            success=False,
        )

        message = "Execution failed: empty command."

        warn(
            f"{tool}: {message}"
        )

        result.add_error(
            message
        )

        result.metadata.update(
            {
                "exit_code": None,
                "timed_out": False,
                "timeout": timeout_value,
                "command": "",
                "resolved_command": "",
            }
        )

        return result

    ###########################################################################
    # Timeout Range Validation
    ###########################################################################

    if timeout_value <= 0:
        result = ExecutionResult(
            tool=tool,
            capability=capability,
            success=False,
        )

        message = (
            "Execution failed: timeout must be "
            "greater than zero."
        )

        warn(
            f"{tool}: {message}"
        )

        result.add_error(
            message
        )

        result.metadata.update(
            {
                "exit_code": None,
                "timed_out": False,
                "timeout": timeout_value,
                "command": command,
                "resolved_command": (
                    shlex.join(
                        resolved_command
                    )
                    if isinstance(
                        resolved_command,
                        list,
                    )
                    else resolved_command
                ),
            }
        )

        return result

    info(
        f"Running {tool}: {command}"
    )

    started_at = time.monotonic()

    result = ExecutionResult(
        tool=tool,
        capability=capability,
        success=False,
    )

    output_path: Path | None = None

    if outfile:
        output_path = Path(
            outfile
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    ###########################################################################
    # Environment
    ###########################################################################

    merged_env: dict[str, str]

    if env is not None:
        merged_env = os.environ.copy()
        merged_env.update(
            {
                str(key): str(value)
                for key, value in env.items()
            }
        )
    else:
        merged_env = os.environ.copy()

    ###########################################################################
    # Execute
    ###########################################################################

    try:
        if isinstance(
            cmd,
            list,
        ):
            if not resolved_command:
                raise FileNotFoundError(
                    "Empty command."
                )

            completed = subprocess.run(
                resolved_command,
                shell=False,
                cwd=cwd,
                env=merged_env,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_value,
            )

        else:
            completed = subprocess.run(
                resolved_command,
                shell=True,
                cwd=cwd,
                env=merged_env,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_value,
            )

    except subprocess.TimeoutExpired as exc:
        duration = (
            time.monotonic()
            - started_at
        )

        stdout = _decode_output(
            exc.stdout
        )

        stderr = _decode_output(
            exc.stderr
        )

        message = (
            f"Command timed out after "
            f"{timeout_value}s."
        )

        warn(
            f"{tool}: {message}"
        )

        _write_execution_output(
            output_path,
            stdout=stdout,
            stderr=stderr,
            suffix=(
                "\n\n"
                f"[ScopeForgeX] {message}\n"
            ),
        )

        result.success = False
        result.stdout = stdout
        result.stderr = stderr

        result.add_error(
            message
        )

        result.metadata.update(
            {
                "exit_code": None,
                "timed_out": True,
                "timeout": timeout_value,
                "command": command,
                "resolved_command": (
                    shlex.join(
                        resolved_command
                    )
                    if isinstance(
                        resolved_command,
                        list,
                    )
                    else resolved_command
                ),
            }
        )

        result.duration = duration

        if output_path:
            result.add_artifact(
                str(output_path)
            )

        return result

    except OSError as exc:
        duration = (
            time.monotonic()
            - started_at
        )

        message = (
            f"Execution failed: {exc}"
        )

        warn(
            f"{tool}: {message}"
        )

        _write_execution_output(
            output_path,
            suffix=(
                "\n\n"
                f"[ScopeForgeX] {message}\n"
            ),
        )

        result.success = False

        result.add_error(
            message
        )

        result.metadata.update(
            {
                "exit_code": None,
                "timed_out": False,
                "timeout": timeout_value,
                "command": command,
                "resolved_command": (
                    shlex.join(
                        resolved_command
                    )
                    if isinstance(
                        resolved_command,
                        list,
                    )
                    else resolved_command
                ),
            }
        )

        result.duration = duration

        if output_path:
            result.add_artifact(
                str(output_path)
            )

        return result

    except Exception as exc:
        duration = (
            time.monotonic()
            - started_at
        )

        message = (
            f"Unexpected execution error: {exc}"
        )

        warn(
            f"{tool}: {message}"
        )

        _write_execution_output(
            output_path,
            suffix=(
                "\n\n"
                f"[ScopeForgeX] {message}\n"
            ),
        )

        result.success = False

        result.add_error(
            message
        )

        result.metadata.update(
            {
                "exit_code": None,
                "timed_out": False,
                "timeout": timeout_value,
                "command": command,
                "resolved_command": (
                    shlex.join(
                        resolved_command
                    )
                    if isinstance(
                        resolved_command,
                        list,
                    )
                    else resolved_command
                ),
            }
        )

        result.duration = duration

        if output_path:
            result.add_artifact(
                str(output_path)
            )

        return result

    ###########################################################################
    # Process Output
    ###########################################################################

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""

    _write_execution_output(
        output_path,
        stdout=stdout,
        stderr=stderr,
    )

    result.stdout = stdout
    result.stderr = stderr

    ###########################################################################
    # Exit Status
    ###########################################################################

    if completed.returncode == 0:
        result.success = True

    else:
        result.success = False

        result.add_error(
            (
                f"Command exited with status "
                f"{completed.returncode}."
            )
        )

    ###########################################################################
    # Warnings
    ###########################################################################

    if stderr.strip():
        result.add_warning(
            stderr.strip()
        )

    ###########################################################################
    # Metadata
    ###########################################################################

    result.metadata.update(
        {
            "exit_code": completed.returncode,
            "timed_out": False,
            "timeout": timeout_value,
            "command": command,
            "resolved_command": (
                shlex.join(
                    resolved_command
                )
                if isinstance(
                    resolved_command,
                    list,
                )
                else resolved_command
            ),
        }
    )

    result.duration = (
        time.monotonic()
        - started_at
    )

    if output_path:
        result.add_artifact(
            str(output_path)
        )

    return result


###############################################################################
# Backward-Compatible Runner
###############################################################################


def run_cmd(
    cmd: str,
    outfile: str | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess | None:
    """
    Backward-compatible command runner.

    Older ScopeForgeX adapters use this function directly.

    Returns:
        subprocess.CompletedProcess on execution,
        or None when execution fails or times out.
    """

    info(
        f"Running: {cmd}"
    )

    try:
        resolved_command = _resolve_command(
            cmd
        )

        if outfile:
            output_path = Path(
                outfile
            )

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with output_path.open(
                "w",
                encoding="utf-8",
            ) as output:

                result = subprocess.run(
                    resolved_command,
                    shell=True,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                    timeout=timeout,
                )

        else:
            result = subprocess.run(
                resolved_command,
                shell=True,
                text=True,
                check=False,
                timeout=timeout,
            )

        return result

    except subprocess.TimeoutExpired:
        warn(
            f"Timeout reached ({timeout}s). "
            "Command stopped."
        )

        if outfile:
            with open(
                outfile,
                "a",
                encoding="utf-8",
            ) as output:
                output.write(
                    "\n\n"
                    f"[ScopeForgeX] Timeout reached ({timeout}s). "
                    "Command stopped.\n"
                )

        return None

    except FileNotFoundError as exc:
        warn(
            f"Executable not found: {exc}"
        )

        return None

    except Exception as exc:
        warn(
            f"Command failed: {exc}"
        )

        if outfile:
            with open(
                outfile,
                "a",
                encoding="utf-8",
            ) as output:
                output.write(
                    "\n\n"
                    f"[ScopeForgeX] ERROR: {exc}\n"
                )

        return None


###############################################################################
# Executable Availability
###############################################################################


def is_command_available(
    command: str,
) -> bool:
    """
    Return whether an executable is available on PATH.

    The command may contain arguments; only the executable portion
    is checked.
    """

    try:
        parts = shlex.split(
            command
        )

        if not parts:
            return False

        executable = parts[0]

    except (
        IndexError,
        ValueError,
    ):
        return False

    return (
        resolve_executable(
            executable
        )
        is not None
    )


###############################################################################
# Command Resolution
###############################################################################


def _resolve_argv(
    cmd: list[str],
    env: dict[str, str] | None = None,
) -> list[str]:
    """
    Resolve the executable of an argument-vector command.

    The argument list is preserved exactly; only argv[0] is replaced
    when a preferred executable path is available.

    When an environment mapping is supplied, its PATH is used for
    PATH-based executable resolution.
    """

    if not cmd:
        return []

    executable = str(
        cmd[0]
    )

    if not executable.strip():
        return []

    if (
        os.path.isabs(
            executable
        )
        or "/" in executable
    ):
        return cmd

    resolved = resolve_executable(
        executable,
        env=env,
    )

    if resolved is None:
        return cmd

    return [
        resolved,
        *cmd[1:],
    ]


def _resolve_command(
    cmd: str,
    env: dict[str, str] | None = None,
) -> str:
    """
    Resolve the executable at the beginning of a shell command.

    ScopeForgeX commonly uses Go-based security tools installed under:

        ~/go/bin

    Some Python environments can expose unrelated executables with the
    same names. For example, the Python package `httpx` can shadow
    ProjectDiscovery's Go-based `httpx`.

    Therefore, when ~/go/bin/<executable> exists and is executable,
    it is preferred for command resolution.

    Explicit executable paths are never modified.
    """

    try:
        parts = shlex.split(
            cmd
        )

    except ValueError:
        return cmd

    if not parts:
        return cmd

    executable = parts[0]

    ###########################################################################
    # Explicit Path
    ###########################################################################

    if (
        os.path.isabs(
            executable
        )
        or "/" in executable
    ):
        return cmd

    ###########################################################################
    # Resolve Executable
    ###########################################################################

    resolved = resolve_executable(
        executable,
        env=env,
    )

    if resolved is None:
        return cmd

    ###########################################################################
    # Replace Only Executable Token
    ###########################################################################

    remainder = cmd[
        len(executable):
    ]

    return (
        shlex.quote(
            resolved
        )
        + remainder
    )


###############################################################################
# Output Handling
###############################################################################


def _write_execution_output(
    output_path: Path | None,
    *,
    stdout: str = "",
    stderr: str = "",
    suffix: str = "",
) -> None:
    """
    Persist command output when an output file was requested.

    stdout and stderr remain separately available through ExecutionResult,
    while the artifact receives a combined human-readable execution log.
    """

    if output_path is None:
        return

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
        errors="replace",
    ) as output:

        if stdout:
            output.write(
                stdout
            )

        if stderr:
            if stdout and not stdout.endswith(
                "\n"
            ):
                output.write(
                    "\n"
                )

            output.write(
                stderr
            )

        if suffix:
            output.write(
                suffix
            )


###############################################################################
# Output Normalization
###############################################################################


def _decode_output(
    value: Any,
) -> str:
    """
    Normalize subprocess output into text.
    """

    if value is None:
        return ""

    if isinstance(
        value,
        bytes,
    ):
        return value.decode(
            "utf-8",
            errors="replace",
        )

    return str(
        value
    )
