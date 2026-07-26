"""
ScopeForgeX Stage 3
===================

Vulnerability Identification stage.

Runs all registered Stage 3 vulnerability discovery tools.

v0.4.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import err, info, ok, stage, warn


def _print_tool_result(result):
    """
    Display the outcome of a tool execution.
    """

    if result.ran:
        ok(f"Tool completed: {result.name}")
    else:
        warn(f"Tool skipped/failed: {result.name}")

    if result.notes:
        info(f"Notes: {result.notes}")

    if result.output_files:
        for output in result.output_files:
            info(f"Output: {output}")
    else:
        info("Output: (none)")


def stage3_vuln(ctx: dict):
    """
    Execute Stage 3 vulnerability identification.
    """

    stage("STAGE 3 — VULNERABILITY IDENTIFICATION", "red")

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 3
    ]

    if not tools:
        err("No Stage 3 tools registered.")
        return

    for tool in tools:
        result = tool.run(ctx)
        _print_tool_result(result)

    ok("Stage 3 vulnerability identification finished ✅")
