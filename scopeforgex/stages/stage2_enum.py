"""
ScopeForgeX Stage 2
===================

Enumeration stage.

Runs the appropriate enumeration tools depending on the
selected target type.

v0.4.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import err, info, ok, stage, warn


# ----------------------------------------------------------------------
# Tool selection
# ----------------------------------------------------------------------

_TARGET_TOOLSETS = {
    "web": {
        "whatweb",
        "wafw00f",
        "ffuf",
    },
    "network": {
        "enum4linux-ng",
        "snmpwalk",
    },
}


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


def stage2_enum(ctx: dict):
    """
    Execute Stage 2 enumeration.
    """

    stage("STAGE 2 — ENUMERATION", "yellow")

    target_type = ctx.get("target_type")

    allowed_tools = _TARGET_TOOLSETS.get(target_type)

    if allowed_tools is None:
        err(f"Unsupported target type: {target_type}")
        return

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 2 and tool.name in allowed_tools
    ]

    if not tools:
        err(f"No Stage 2 tools registered for target type: {target_type}")
        return

    for tool in tools:
        result = tool.run(ctx)
        _print_tool_result(result)

    ok("Stage 2 enumeration finished ✅")
