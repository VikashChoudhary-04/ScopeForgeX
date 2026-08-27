"""
ScopeForgeX Stage 1 — Reconnaissance
====================================

Executes reconnaissance tools selected from the canonical tool registry.

Tool selection is capability/phase-oriented. The stage orchestrator does not
construct tool-specific commands or maintain a second list of integrations.

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
    Display the outcome of a single reconnaissance tool.

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


def stage1_recon(
    ctx: dict,
) -> None:
    """
    Execute reconnaissance tools registered for the current profile.

    Supported profiles:

        - full_safe
        - fast

    The registry remains the single source of truth for reconnaissance
    integrations. Profile filtering only controls which registered tools are
    selected for execution.
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
        if tool.phase
        == AssessmentPhase.RECONNAISSANCE
    ]

    if not tools:
        err(
            "No reconnaissance tools registered."
        )
        return

    ###########################################################################
    # Fast Profile
    ###########################################################################

    if profile == "fast":

        allowed_tools = {
            "subhunt",
            "amass",
        }

        warn(
            "FAST mode: running focused "
            "attack-surface discovery tools."
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
            "using full_safe reconnaissance selection."
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
        "Stage 1 reconnaissance finished ✅"
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage1_recon",
]
