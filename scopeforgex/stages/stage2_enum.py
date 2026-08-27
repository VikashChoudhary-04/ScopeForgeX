"""
ScopeForgeX Stage 2 — Enumeration
=================================

Executes enumeration tools selected from the canonical tool registry.

Tool selection is phase-oriented. The stage orchestrator does not construct
tool-specific commands or maintain a second integration registry.

v1.1.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.runtime.enums import AssessmentPhase
from scopeforgex.ui import err, info, ok, stage, warn


###############################################################################
# Result Display
###############################################################################


def _print_tool_result(
    result,
) -> None:
    """
    Display the outcome of a single enumeration tool.

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


###############################################################################
# Stage Execution
###############################################################################


def stage2_enum(
    ctx: dict,
) -> None:
    """
    Execute enumeration tools registered for the current profile.

    Supported profiles:

        - full_safe
        - fast

    The canonical tool registry remains the single source of truth for
    enumeration integrations.
    """

    stage(
        "STAGE 2 — ENUMERATION",
        "green",
    )

    profile = ctx.get(
        "profile",
        "full_safe",
    )

    ###########################################################################
    # Registry Selection
    ###########################################################################

    tools = [
        tool
        for tool in build_registry()
        if tool.phase
        == AssessmentPhase.ENUMERATION
    ]

    if not tools:
        err(
            "No enumeration tools registered."
        )
        return

    ###########################################################################
    # Fast Profile
    ###########################################################################

    if profile == "fast":

        allowed_tools = {
            "httpx",
            "whatweb",
        }

        warn(
            "FAST mode: running lightweight "
            "web enumeration tools only."
        )

        tools = [
            tool
            for tool in tools
            if tool.name in allowed_tools
        ]

    ###########################################################################
    # Unknown Profile
    ###########################################################################

    elif profile != "full_safe":

        warn(
            f"Unknown profile '{profile}'; "
            "using full_safe enumeration selection."
        )

    ###########################################################################
    # Execution
    ###########################################################################

    for tool in tools:

        try:
            result = tool.run(
                ctx
            )

        except Exception as exc:
            warn(
                f"Tool execution error: "
                f"{tool.name}: {exc}"
            )
            continue

        _print_tool_result(
            result
        )

    ok(
        "Stage 2 enumeration finished ✅"
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage2_enum",
]
