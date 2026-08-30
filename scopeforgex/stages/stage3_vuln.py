"""
ScopeForgeX — Stage 3 Vulnerability Identification
===================================================

Stage 3 of the ScopeForgeX ethical hacking workflow.

Responsibilities
----------------

- Execute registered Stage 3 vulnerability-identification tools.
- Consume normalized reconnaissance/enumeration pipeline artifacts.
- Preserve tool results and generated vulnerability artifacts.
- Display consistent execution status in the terminal.
- Keep vulnerability identification separate from exploitation.
- Allow individual tools to report skipped or failed execution without
  terminating the complete workflow.

Current Stage 3 Integration
---------------------------

Nuclei
    |
    +--> hosts_final.txt
    |       |
    |       v
    |   nuclei_hosts.txt
    |       |
    |       v
    |   nuclei_hosts.log
    |
    +--> urls_final.txt
            |
            v
        nuclei_urls.txt
            |
            v
        nuclei_urls.log

Combined findings are written to:

    vuln/nuclei.txt

Design Principles
-----------------

- Stage orchestration remains separate from tool implementation.
- Tools are obtained from the central registry.
- The stage does not execute subprocesses directly.
- The stage does not perform exploitation.
- The stage does not independently confirm vulnerabilities.
- Tool output remains available as assessment evidence.
- Missing tools are reported through the normal ToolResult contract.
- Stage 3 remains compatible with FAST and FULL_SAFE workflows.

v1.3.0
"""

from __future__ import annotations

from typing import Any

from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import (
    err,
    info,
    ok,
    stage,
    warn,
)


###############################################################################
# Tool Result Display
###############################################################################


def _print_tool_result(
    result: Any,
) -> None:
    """
    Display a standardized summary of a Stage 3 tool result.

    The function intentionally depends only on the ToolResult interface used
    by the existing ScopeForgeX registry and integrations.
    """

    if result is None:
        warn(
            "Stage 3 tool returned no result."
        )
        return

    if getattr(
        result,
        "ran",
        False,
    ):
        ok(
            f"Tool completed: {result.name}"
        )

    else:
        warn(
            f"Tool skipped/failed: {result.name}"
        )

    notes = getattr(
        result,
        "notes",
        None,
    )

    if notes:
        info(
            f"Notes: {notes}"
        )

    output_files = getattr(
        result,
        "output_files",
        None,
    )

    if output_files:

        for file_path in output_files:

            if file_path:
                info(
                    f"Output: {file_path}"
                )

    else:
        info(
            "Output: (none)"
        )


###############################################################################
# Stage 3
###############################################################################


def stage3_vuln(
    ctx: dict,
) -> None:
    """
    Execute all registered Stage 3 vulnerability-identification tools.

    Args:
        ctx:
            Shared ScopeForgeX workflow context.

    Returns:
        None.

    The stage deliberately delegates execution to registered tool adapters.
    This keeps the stage independent from the concrete vulnerability scanner
    implementation.
    """

    stage(
        "STAGE 3 — VULNERABILITY IDENTIFICATION",
        "red",
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

    for tool in tools:

        try:

            result = tool.run(
                ctx
            )

            _print_tool_result(
                result
            )

        except Exception as exc:

            # A single integration failure must not prevent the workflow from
            # recording the remaining Stage 3 results.
            err(
                f"Stage 3 tool '{tool.name}' failed: {exc}"
            )

    ok(
        "Stage 3 vulnerability identification finished ✅"
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "stage3_vuln",
]
