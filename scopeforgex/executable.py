"""
ScopeForgeX Executable Resolution
=================================

Canonical executable resolution shared by dependency detection and
command execution.

ScopeForgeX prefers Go-installed security tools under ``~/go/bin``
before falling back to the current PATH. This prevents unrelated
executables exposed by Python environments from shadowing the
canonical security-tool binary.

v3.0.0
"""

from __future__ import annotations

import os
import pwd
import shutil


def resolve_executable(
    executable: str,
    env: dict[str, str] | None = None,
) -> str | None:
    """
    Resolve an executable using ScopeForgeX's canonical precedence.

    Resolution order:

    1. ``~/go/bin/<executable>``
    2. ``PATH`` from ``env`` when supplied
    3. The current process ``PATH``

    Explicit paths are returned only when they point to an executable
    file.

    Args:
        executable:
            Executable name or explicit executable path.

        env:
            Optional environment mapping whose ``PATH`` value should be
            used for PATH-based resolution.

    Returns:
        The resolved executable path when an executable is available,
        otherwise ``None``.
    """

    executable = str(executable)

    if not executable.strip():
        return None

    if (
        os.path.isabs(executable)
        or "/" in executable
    ):
        if (
            os.path.isfile(executable)
            and os.access(
                executable,
                os.X_OK,
            )
        ):
            return executable

        return None

    home = os.path.expanduser("~")

    # When ScopeForgeX is launched through sudo, ``~`` may resolve to
    # ``/root`` even though the security tools were installed for the
    # invoking user. Prefer that user's home directory for the canonical
    # Go security-tool location.
    sudo_user = (
        env.get("SUDO_USER")
        if env is not None
        else os.environ.get("SUDO_USER")
    )

    if sudo_user:
        try:
            home = pwd.getpwnam(
                str(sudo_user)
            ).pw_dir
        except (
            KeyError,
            TypeError,
            ValueError,
        ):
            pass

    go_binary = os.path.join(
        home,
        "go",
        "bin",
        executable,
    )

    if (
        os.path.isfile(go_binary)
        and os.access(
            go_binary,
            os.X_OK,
        )
    ):
        return go_binary

    path = None

    if env is not None:
        path = env.get("PATH")

    if path is None:
        path = os.environ.get("PATH")

    resolved_from_path = shutil.which(
        executable,
        path=path,
    )

    if resolved_from_path:
        return resolved_from_path

    return None


__all__ = [
    "resolve_executable",
]
