"""
ScopeForgeX Stage 3 - Vulnerability Assessment
==============================================

Executes Stage 3 vulnerability assessment tools
registered in the tool registry.

Uses the canonical ExecutionResult model.

v0.5.0
"""

from __future__ import annotations

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


def _print_tool_result(result):
    """
    Display the outcome of a single Stage 3 tool.

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


def stage3_vuln(ctx: dict):
    """
    Execute all Stage 3 vulnerability assessment tools
    registered for the current execution profile.

    Supported profiles:
        - full_safe (default)
        - fast
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
        return

    if profile == "fast":

        allowed_tools = {
            "nuclei",
        }

        warn(
            "FAST mode: running vulnerability "
            "scanner profile."
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
        "Stage 3 vulnerability assessment finished ✅"
    )


__all__ = [
    "stage3_vuln",
]
