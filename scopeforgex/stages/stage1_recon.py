"""
ScopeForgeX Stage 1 — Reconnaissance
====================================

Executes reconnaissance adapters selected from the canonical tool registry.

The stage orchestrator does not construct tool-specific commands and does not
maintain a second integration list.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.registry.tool_registry import (
    create_tool_adapter,
    get_tools_by_phase,
)
from scopeforgex.ui import err, info, ok, stage, warn


###############################################################################
# Result Display
###############################################################################


def _print_tool_result(
    result: Any,
) -> None:
    """Display the outcome of a single reconnaissance tool."""

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
# Context
###############################################################################


def _build_tool_context(
    ctx: dict[str, Any],
) -> ToolContext:
    """
    Convert the legacy workflow dictionary into the canonical ToolContext.

    The stage orchestrator performs only context translation. Tool-specific
    behavior remains inside each ToolAdapter.
    """

    target = str(
        ctx.get(
            "target",
            "",
        )
    ).strip()

    outdir = ctx.get(
        "outdir"
    )

    if not outdir:
        raise ValueError(
            "Stage 1 requires an output directory."
        )

    options = ctx.get(
        "options",
        {},
    )

    if not isinstance(
        options,
        dict,
    ):
        options = dict(
            options
        )

    input_data = ctx.get(
        "input_data",
        (),
    )

    if isinstance(
        input_data,
        str,
    ):
        input_data = (
            input_data,
        )

    return ToolContext(
        target=target,
        output_dir=Path(
            str(outdir)
        ),
        profile=str(
            ctx.get(
                "profile",
                "full_safe",
            )
        ),
        options=options,
        input_data=tuple(
            input_data
        ),
    )


###############################################################################
# Stage Execution
###############################################################################


def stage1_recon(
    ctx: dict[str, Any],
) -> None:
    """
    Execute reconnaissance tools registered for the current profile.
    """

    stage(
        "STAGE 1 — RECON",
        "green",
    )

    profile = str(
        ctx.get(
            "profile",
            "full_safe",
        )
    )

    try:
        tool_context = _build_tool_context(
            ctx
        )
    except ValueError as exc:
        err(
            str(exc)
        )
        return

    tool_names = list(
        get_tools_by_phase(
            "reconnaissance"
        )
    )

    if not tool_names:
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

        tool_names = [
            name
            for name in tool_names
            if name in allowed_tools
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

    for name in tool_names:

        try:
            adapter = create_tool_adapter(
                name,
                context=tool_context,
            )

            result = adapter.run()

        except Exception as exc:
            warn(
                f"Tool execution error: "
                f"{name}: {exc}"
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
