"""
ScopeForgeX Stage 5
===================

Post-Exploitation Preparation stage.

This stage prepares post-exploitation and credential-related
commands but requires explicit user confirmation before any
registered tool is executed.

v0.4.0
"""

from __future__ import annotations

import questionary

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import ok, stage, warn


def stage5_post(ctx: dict):
    """
    Execute Stage 5 post-exploitation preparation.
    """

    stage("STAGE 5 — POST/CREDS PREP (Prepared)", "magenta")

    warn(
        "This stage prepares post-exploitation commands and "
        "requires explicit confirmation before execution."
    )

    if not questionary.confirm("Continue?").ask():
        warn("Stage 5 skipped by user.")
        return

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 5
    ]

    if not tools:
        warn("No Stage 5 tools registered.")
        return

    for tool in tools:
        result = tool.run(ctx)

        if result.ran:
            ok(f"Tool completed: {result.name}")
        else:
            warn(f"Tool skipped/failed: {result.name}")

    ok("Stage 5 post-exploitation preparation finished ✅")
