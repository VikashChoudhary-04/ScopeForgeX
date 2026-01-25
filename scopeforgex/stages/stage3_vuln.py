from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok

def stage3_vuln(ctx: dict):
    stage("STAGE 3 — VULNERABILITY IDENTIFICATION", "red")
    tools = [t for t in build_registry() if t.stage == 3]
    for tool in tools:
        tool.run(ctx)
    ok("Stage 3 vuln finished ✅")
