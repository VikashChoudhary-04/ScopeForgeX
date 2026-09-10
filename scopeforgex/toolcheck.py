"""
ScopeForgeX Tool Detection
==========================

Utilities for detecting external executables required by
ScopeForgeX tools.

v0.4.0
"""

from __future__ import annotations

from scopeforgex.executable import resolve_executable


def is_tool_installed(tool_name: str) -> bool:
    """
    Check whether a canonical ScopeForgeX executable is available.

    Executable resolution uses the same policy as command execution,
    including the preferred ``~/go/bin`` location.

    Args:
        tool_name:
            Executable name (e.g. "nuclei", "httpx", "ffuf").

    Returns:
        True if the executable can be resolved, otherwise False.
    """

    if not tool_name:
        return False

    return resolve_executable(
        tool_name
    ) is not None


__all__ = [
    "is_tool_installed",
]
