from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from scopeforgex.utils import load_yaml
from scopeforgex.state import save_last_run
from scopeforgex.ui import stage, ok, summary_table

from scopeforgex.stages.stage0_scope import stage0_scope
from scopeforgex.stages.stage1_recon import stage1_recon
from scopeforgex.stages.stage2_enum import stage2_enum
from scopeforgex.stages.stage3_vuln import stage3_vuln
from scopeforgex.stages.stage4_exploit import stage4_exploit
from scopeforgex.stages.stage5_post import stage5_post
from scopeforgex.stages.stage6_report_cleanup import stage6_reporting

def run_profile(profile_name: str):
    profiles = load_yaml("config/profiles.yaml")["profiles"]
    if profile_name not in profiles:
        raise SystemExit("Unknown profile")

    enabled = profiles[profile_name]["enabled_stages"]
    ctx = {}

    stage("STAGE 0 — SCOPE", "blue")
    stage0_scope(ctx)

    total = len(enabled)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
    ) as progress:
        task = progress.add_task(f"Running profile: {profile_name}", total=total)

        for s in enabled:
            if s == 1:
                stage1_recon(ctx)
            elif s == 2:
                stage2_enum(ctx)
            elif s == 3:
                stage3_vuln(ctx)
            elif s == 4:
                stage4_exploit(ctx)
            elif s == 5:
                stage5_post(ctx)
            elif s == 6:
                stage6_reporting(ctx)

            progress.advance(task)

    save_last_run(ctx)
    ok("Workflow completed ✅")

    summary_table(
        "ScopeForgeX Summary",
        [
            ("Profile", profile_name),
            ("Target Type", ctx.get("target_type", "-")),
            ("Target", ctx.get("target", "-")),
            ("Output Directory", ctx.get("outdir", "-")),
        ]
    )
