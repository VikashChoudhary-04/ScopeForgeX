"""
ScopeForgeX Stage 3 - Vulnerability Assessment
==============================================

Executes all registered Stage 3 vulnerability assessment tools.

Uses canonical ExecutionResult handling.

v0.5.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import (
    stage,
    ok,
    warn,
    err,
    info,
)


###############################################################################
# Result Display
###############################################################################


def _print_tool_result(
    result,
) -> None:
    """
    Display the outcome of a single Stage 3 tool.
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


###############################################################################
# Stage Execution
###############################################################################


def stage3_vuln(
    ctx: dict,
):
    """
    Execute Stage 3 vulnerability tools.

    Returns:
        list of ExecutionResult objects.
    """

    stage(
        "STAGE 3 — VULNERABILITY ASSESSMENT",
        "green",
    )

    profile = ctx.get(
        "profile",
        "full_safe",
    )

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 3
    ]

    if not tools:

        err(
            "No Stage 3 tools registered."
        )

        return []


    if profile == "fast":

        allowed_tools = {
            "nuclei",
        }

        warn(
            "FAST mode: running vulnerability scanner profile."
        )

        tools = [
            tool
            for tool in tools
            if tool.name in allowed_tools
        ]


    results = []


    for tool in tools:

        result = tool.run(
            ctx
        )

        results.append(
            result
        )

        _print_tool_result(
            result
        )


    ctx[
        "stage3_results"
    ] = results


    ok(
        "Stage 3 vulnerability assessment finished ✅"
    )


    return results


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage3_vuln",
]
