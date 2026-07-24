from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn, err, info


WEB_TOOLS = {
    "whatweb",
    "wafw00f",
    "ffuf",
}

NETWORK_TOOLS = {
    "enum4linux-ng",
    "snmpwalk",
}


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


def stage2_enum(ctx: dict):
    stage("STAGE 2 — ENUMERATION", "yellow")

    tools = [t for t in build_registry() if t.stage == 2]

    target_type = ctx.get("target_type")

    if target_type == "web":
        tools = [t for t in tools if t.name in WEB_TOOLS]
    elif target_type == "network":
        tools = [t for t in tools if t.name in NETWORK_TOOLS]
    else:
        err(f"Unsupported target type: {target_type}")
        return

    if not tools:
        err(f"No Stage 2 tools registered for target type: {target_type}")
        return

    for tool in tools:
        result = tool.run(ctx)
        _print_tool_result(result)

    ok("Stage 2 enumeration finished ✅")
