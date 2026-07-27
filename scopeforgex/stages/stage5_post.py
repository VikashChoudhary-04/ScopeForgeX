"""
ScopeForgeX Stage 5 - Post-Exploitation Preparation
===================================================

Executes Stage 5 post-exploitation preparation tools
registered in the tool registry.

ScopeForgeX intentionally does NOT execute
post-exploitation tools automatically.

Tools only prepare reproducible commands that an
authorized operator may review and execute manually.

Uses the canonical ExecutionResult model.

v0.5.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


def _print_tool_result(result):
    """
    Display the outcome of a single Stage 5 tool.

    Uses ExecutionResult fields:
        success
        tool
        artifacts
        findings
        warnings
        errors
        metadata
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

    if result.findings:
        info(
            f"Findings: {len(result.findings)}"
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


def stage5_post(ctx: dict):
    """
    Execute all Stage 5 post-exploitation preparation
    tools registered for the current execution profile.

    Supported profiles:
        - full_safe (default)
        - fast
    """

    stage(
        "STAGE 5 — POST-EXPLOITATION PREPARATION",
        "green",
    )

    profile = ctx.get(
        "profile",
        "full_safe",
    )

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 5
    ]

    if not tools:
        err(
            "No Stage 5 tools registered."
        )
        return

    if profile == "fast":

        allowed_tools = {
            "chisel",
            "ssh",
        }

        warn(
            "FAST mode: running limited "
            "post-exploitation preparation tools."
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
        "Stage 5 post-exploitation preparation finished ✅"
    )


__all__ = [
    "stage5_post",
]
