"""
ScopeForgeX Stage 3 — Vulnerability Assessment
===============================================

Executes vulnerability-assessment tools selected from the canonical tool
registry.

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
    Display the outcome of a single vulnerability-assessment tool.

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


def stage3_vuln(
    ctx: dict,
) -> None:
    """
    Execute vulnerability-assessment tools registered for the current
    execution profile.

    Supported profiles:

        - full_safe
        - fast

    Targeted validation tools such as SQLMap, Dalfox, JWT Tool and SSTImap
    remain in the later validation phase and are not automatically executed
    here.
    """

    stage(
        "STAGE 3 — VULNERABILITY ASSESSMENT",
        "red",
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
        == AssessmentPhase.VULNERABILITY_ASSESSMENT
    ]

    if not tools:
        err(
            "No vulnerability-assessment tools registered."
        )
        return

    ###########################################################################
    # Fast Profile
    ###########################################################################

    if profile == "fast":

        allowed_tools = {
            "nuclei",
        }

        warn(
            "FAST mode: running lightweight "
            "vulnerability assessment only."
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
            "using full_safe vulnerability-assessment selection."
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
        "Stage 3 vulnerability assessment finished ✅"
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage3_vuln",
]
