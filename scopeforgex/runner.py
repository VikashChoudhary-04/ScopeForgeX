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

v1.1.0
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.ui import info, warn


###############################################################################
# Command Execution
###############################################################################


def run_command(
    *,
    tool: str,
    capability: str,
    cmd: str,
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
            Fully constructed shell command.

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

    info(
        f"Running {tool}: {cmd}"
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
            env
        )
    else:
        merged_env = os.environ.copy()

    ###########################################################################
    # Executable Resolution
    ###########################################################################

    resolved_command = _resolve_command(
        cmd,
        env=merged_env,
    )

    ###########################################################################
    # Execute
    ###########################################################################

    try:
        completed = subprocess.run(
            resolved_command,
            shell=True,
            cwd=cwd,
            env=merged_env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
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
            f"Command timed out after {timeout}s."
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
                "timeout": timeout,
                "command": cmd,
                "resolved_command": resolved_command,
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
                "timeout": timeout,
                "command": cmd,
                "resolved_command": resolved_command,
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
                "timeout": timeout,
                "command": cmd,
                "resolved_command": resolved_command,
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
            "timeout": timeout,
            "command": cmd,
            "resolved_command": resolved_command,
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
        executable = shlex.split(
            command
        )[0]

    except (IndexError, ValueError):
        return False

    return (
        shutil.which(
            executable
        )
        is not None
    )


###############################################################################
# Command Resolution
###############################################################################


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
    # Build Candidate Paths
    ###########################################################################

    candidates: list[str] = []

    home = os.path.expanduser(
        "~"
    )

    go_binary = os.path.join(
        home,
        "go",
        "bin",
        executable,
    )

    candidates.append(
        go_binary
    )

    ###########################################################################
    # PATH Resolution
    ###########################################################################

    path = None

    if env is not None:
        path = env.get(
            "PATH"
        )

    if path is None:
        path = os.environ.get(
            "PATH"
        )

    resolved_from_path = shutil.which(
        executable,
        path=path,
    )

    if resolved_from_path:
        candidates.append(
            resolved_from_path
        )

    ###########################################################################
    # Select First Valid Executable
    ###########################################################################

    resolved: str | None = None

    for candidate in candidates:

        if (
            os.path.isfile(candidate)
            and os.access(
                candidate,
                os.X_OK,
            )
        ):
            resolved = candidate
            break

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
