from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


def _print_tool_result(result):
    """Display the outcome of a single Stage 1 tool."""

    if result.ran:
        ok(f"Tool completed: {result.name}")
    else:
        warn(f"Tool skipped/failed: {result.name}")

    if result.notes:
        info(f"Notes: {result.notes}")

    if result.output_files:
        for output in result.output_files:
            info(f"Output: {output}")
    else:
        info("Output: (none)")


def stage1_recon(ctx: dict):
    """
    Execute all Stage 1 reconnaissance tools registered for the
    current execution profile.

    Supported profiles:
        - full_safe (default)
        - fast
    """

    stage("STAGE 1 — RECON", "green")

    profile = ctx.get("profile", "full_safe")

    tools = [tool for tool in build_registry() if tool.stage == 1]

    if not tools:
        err("No Stage 1 tools registered.")
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
        result = tool.run(ctx)
        _print_tool_result(result)

    ok("Stage 1 recon finished ✅")


# ---------------------------------------------------------------------
# v0.4.0
#
# Stage 1 supports multiple discovery producers.
# Pipeline builders should preserve existing hosts_raw.txt so that
# network and web discoveries can be merged before downstream stages.
# ---------------------------------------------------------------------
