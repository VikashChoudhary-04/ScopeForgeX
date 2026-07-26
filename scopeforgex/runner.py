"""
ScopeForgeX Command Runner
==========================

Shared command execution wrapper used by all tools.

Features:
- Consistent logging
- Output redirection
- Timeout handling
- Graceful failure
- Backward-compatible API

v0.4.0
"""

from __future__ import annotations

import os
import subprocess

from scopeforgex.ui import info, warn


def run_cmd(
    cmd: str,
    outfile: str | None = None,
    timeout: int = 900,
) -> subprocess.CompletedProcess | None:
    """
    Execute a shell command.

    Args:
        cmd:
            Shell command to execute.

        outfile:
            Optional file that receives stdout and stderr.

        timeout:
            Maximum execution time in seconds.

    Returns:
        subprocess.CompletedProcess on successful execution,
        or None if execution failed or timed out.
    """

    info(f"Running: {cmd}")

    try:
        if outfile:
            os.makedirs(os.path.dirname(outfile), exist_ok=True)

            with open(outfile, "w", encoding="utf-8") as output:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                    timeout=timeout,
                )
        else:
            result = subprocess.run(
                cmd,
                shell=True,
                text=True,
                check=False,
                timeout=timeout,
            )

        return result

    except subprocess.TimeoutExpired:
        warn(f"Timeout reached ({timeout}s). Command stopped.")

        if outfile:
            with open(outfile, "a", encoding="utf-8") as output:
                output.write(
                    "\n\n"
                    f"[ScopeForgeX] Timeout reached ({timeout}s). "
                    "Command stopped.\n"
                )

        return None

    except FileNotFoundError as exc:
        warn(f"Executable not found: {exc}")
        return None

    except Exception as exc:
        warn(f"Command failed: {exc}")

        if outfile:
            with open(outfile, "a", encoding="utf-8") as output:
                output.write(
                    "\n\n"
                    f"[ScopeForgeX] ERROR: {exc}\n"
                )

        return None
