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
* Future retry support
* Future parallel execution support
* Backward-compatible run_cmd() API

v0.4.0
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scopeforgex.ui import info, warn

###############################################################################
# Defaults
###############################################################################

DEFAULT_TIMEOUT = 900


###############################################################################
# Execution Result
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
    Create output directory if required.
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
    Append a message to the log file.
    """

    if outfile is None:
        return

    with outfile.open(
        "a",
        encoding="utf-8",
    ) as fp:

        fp.write("\n")
        fp.write(message.rstrip())
        fp.write("\n")


def _execute(
    execution: CommandExecution,
) -> subprocess.CompletedProcess:

    info(
        f"Running: {execution.command}"
    )

    if execution.outfile:

        with execution.outfile.open(
            "w",
            encoding="utf-8",
        ) as stream:

            return subprocess.run(
                execution.command,
                shell=True,
                stdout=stream,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=execution.timeout,
                cwd=execution.cwd,
                env=execution.environment,
            )

    return subprocess.run(
        execution.command,
        shell=True,
        text=True,
        check=False,
        timeout=execution.timeout,
        cwd=execution.cwd,
        env=execution.environment,
    )
###############################################################################
# Public API
###############################################################################


def run_cmd(
    cmd: str,
    outfile: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> subprocess.CompletedProcess | None:
    """
    Execute a shell command.

    Parameters
    ----------
    cmd:
        Shell command to execute.

    outfile:
        Optional file receiving stdout/stderr.

    timeout:
        Maximum execution time in seconds.

    Returns
    -------
    subprocess.CompletedProcess | None
        CompletedProcess on successful execution,
        otherwise None.
    """

    execution = CommandExecution(
        command=cmd,
        timeout=timeout,
        outfile=_prepare_output(outfile),
    )

    try:

        result = _execute(execution)

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
            f"({timeout}s). "
            "Command terminated."
        )

        _append_log(
            execution.outfile,
            (
                "[ScopeForgeX] "
                f"Timeout reached "
                f"({timeout}s). "
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
    Execute a command and return only whether it succeeded.

    This helper is intended for future use where callers only need
    a success/failure indication rather than the full
    CompletedProcess object.
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
    "run_cmd",
    "run_cmd_success",
]
