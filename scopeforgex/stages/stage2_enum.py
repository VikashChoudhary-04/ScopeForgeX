"""
ScopeForgeX Stage 2 - Enumeration
=================================

Executes Stage 2 enumeration tools registered in the tool registry.

v0.5.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


def _print_tool_result(result):
    """
    Display the outcome of a single Stage 2 tool.

    Uses the canonical ExecutionResult model.
    """

    if result.success:
        ok(
            f"Tool completed: {result.tool}"
        )
    else:
        warn(
            f"Tool failed/skipped: {result.tool}"
        )

    if result.metadata:
        info(
            f"Metadata: {result.metadata}"
        )

    if result.errors:
        for error in result.errors:
            warn(
                f"Error: {error}"
            )

    if result.warnings:
        for warning in result.warnings:
            warn(
                f"Warning: {warning}"
            )

    if result.artifacts:
        for artifact in result.artifacts:
            info(
                f"Artifact: {artifact}"
            )
    else:
        info(
            "Artifacts: (none)"
        )


def stage2_enum(ctx: dict):
    """
    Execute all Stage 2 enumeration tools registered for
    the current execution profile.

    Supported profiles:
        - full_safe (default)
        - fast
    """

    stage(
        "STAGE 2 — ENUMERATION",
        "green",
    )

    profile = ctx.get(
        "profile",
        "full_safe",
    )

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 2
    ]

    if not tools:
        err(
            "No Stage 2 tools registered."
        )
        return

    if profile == "fast":

        allowed_tools = {
            "whatweb",
            "wafw00f",
        }

        warn(
            "FAST mode: running lightweight "
            "enumeration tools only."
        )

        tools = [
            tool
            for tool in tools
            if tool.name in allowed_tools
        ]

    for tool in tools:

        result = tool.run(
            ctx
        )

        _print_tool_result(
            result
        )

    ok(
        "Stage 2 enumeration finished ✅"
    )


__all__ = [
    "stage2_enum",
]
