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
* Backward-compatible run_cmd() API

v0.4.1
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from typing import Mapping

from scopeforgex.ui import info
from scopeforgex.ui import warn

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
    Build the common keyword arguments passed to subprocess.run().
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
        CompletedProcess on success,
        otherwise None.
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
    "run_cmd",
    "run_cmd_success",
]
