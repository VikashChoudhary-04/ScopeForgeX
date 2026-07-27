"""
ScopeForgeX Stage 1 — Reconnaissance
====================================

Executes all registered Stage 1 reconnaissance tools.

Supports:
    - full_safe profile
    - fast profile

v0.5.0
"""

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
    Display the outcome of a single Stage 1 tool.

    Supports the new ExecutionResult model.
    """

    if result.success:

        ok(
            f"Tool completed: {result.tool}"
        )

    else:

        warn(
            f"Tool skipped/failed: {result.tool}"
        )

    if result.metadata:

        for key, value in result.metadata.items():

            info(
                f"{key}: {value}"
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
                f"Output: {artifact}"
            )

    else:

        info(
            "Output: (none)"
        )


###############################################################################
# Stage Execution
###############################################################################


def stage1_recon(
    ctx: dict,
) -> None:
    """
    Execute all Stage 1 reconnaissance tools registered for the
    current execution profile.

    Supported profiles:
        - full_safe (default)
        - fast
    """

    stage(
        "STAGE 1 — RECON",
        "green",
    )

    profile = ctx.get(
        "profile",
        "full_safe",
    )

    tools = [
        tool
        for tool in build_registry()
        if tool.stage == 1
    ]

    if not tools:

        err(
            "No Stage 1 tools registered."
        )

        return

    if profile == "fast":

        allowed = {
            "subhunt",
            "pipeline_builder",
        }

        warn(
            "FAST mode: running Subhunt + pipeline builder "
            "(hosts + endpoints)."
        )

        tools = [
            tool
            for tool in tools
            if tool.name in allowed
        ]

    for tool in tools:

        result = tool.run(
            ctx
        )

        _print_tool_result(
            result
        )

    ok(
        "Stage 1 recon finished ✅"
    )


###############################################################################
# Notes
###############################################################################

# Stage 1 supports multiple discovery producers.
#
# Pipeline builders should preserve existing hosts_raw.txt so that
# network and web discoveries can be merged before downstream stages.
