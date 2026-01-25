from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok

def stage1_recon(ctx: dict):
    stage("STAGE 1 — RECON", "green")
    tools = [t for t in build_registry() if t.stage == 1]
    for tool in tools:
        tool.run(ctx)
    ok("Stage 1 recon finished ✅")
