"""
ScopeForgeX Tool Detection
==========================

Utilities for detecting external executables required by
ScopeForgeX tools.

v0.4.0
"""

from __future__ import annotations

import shutil


def is_tool_installed(tool_name: str) -> bool:
    """
    Check whether an executable is available in the current PATH.

    Args:
        tool_name: Executable name (e.g. "nuclei", "httpx", "ffuf").

    Returns:
        True if the executable can be found, otherwise False.
    """

    if not tool_name:
        return False

    return shutil.which(tool_name) is not None
