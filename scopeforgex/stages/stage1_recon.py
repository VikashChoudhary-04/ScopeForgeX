from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


def _print_tool_result(result):
    """
    Standard output after every tool run.
    """
    if result.ran:
        ok(f"Tool completed: {result.name}")
    else:
        warn(f"Tool skipped/failed: {result.name}")

    if result.notes:
        info(f"Notes: {result.notes}")

    if result.output_files:
        for fpath in result.output_files:
            info(f"Output: {fpath}")
    else:
        info("Output: (none)")


def stage1_recon(ctx: dict):
    stage("STAGE 1 — RECON", "green")

    tools = [t for t in build_registry() if t.stage == 1]
    if not tools:
        err("No Stage 1 tools registered.")
        return

    for tool in tools:
        result = tool.run(ctx)
        _print_tool_result(result)

    ok("Stage 1 recon finished ✅")

