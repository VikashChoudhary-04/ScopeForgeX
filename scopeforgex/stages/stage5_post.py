import questionary
from scopeforgex.registry.tool_registry import build_registry
from scopeforgex.ui import stage, ok, warn

def stage5_post(ctx: dict):
    stage("STAGE 5 — POST/CREDS PREP (Prepared)", "magenta")
    warn("This stage prepares commands and requires confirmation.")

    confirm = questionary.confirm("Continue?").ask()
    if not confirm:
        warn("Skipped Stage 5.")
        return

    tools = [t for t in build_registry() if t.stage == 5]
    for tool in tools:
        tool.run(ctx)

    ok("Stage 5 post/creds prep finished ✅")
