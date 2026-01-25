from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok

def stage2_enum(ctx: dict):
    stage("STAGE 2 — ENUMERATION", "yellow")
    tools = [t for t in build_registry() if t.stage == 2]
    for tool in tools:
        tool.run(ctx)
    ok("Stage 2 enumeration finished ✅")
