"""
ScopeForgeX Workflow Engine
===========================

Main workflow orchestrator.

Loads a profile, executes the enabled stages in order,
persists state, and displays a final summary.

v0.4.0
"""

from __future__ import annotations

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.state import save_last_run
from scopeforgex.ui import ok, stage, summary_table
from scopeforgex.utils import load_yaml

from scopeforgex.stages.stage0_scope import stage0_scope
from scopeforgex.stages.stage1_recon import stage1_recon
from scopeforgex.stages.stage2_enum import stage2_enum
from scopeforgex.stages.stage3_vuln import stage3_vuln
from scopeforgex.stages.stage4_exploit import stage4_exploit
from scopeforgex.stages.stage5_post import stage5_post
from scopeforgex.stages.stage6_report_cleanup import stage6_reporting


# ----------------------------------------------------------------------
# Stage registry
# ----------------------------------------------------------------------

_STAGE_FUNCTIONS = {
    1: stage1_recon,
    2: stage2_enum,
    3: stage3_vuln,
    4: stage4_exploit,
    5: stage5_post,
    6: stage6_reporting,
}


def run_profile(profile_name: str):
    """
    Execute a ScopeForgeX profile.
    """

    profiles = load_yaml("config/profiles.yaml").get("profiles", {})

    if profile_name not in profiles:
        raise SystemExit(f"Unknown profile: {profile_name}")

    profile = profiles[profile_name]
    enabled_stages = profile.get("enabled_stages", [])

    ctx: dict = {
        "profile": profile_name,
    }

    # --------------------------------------------------------------
    # Stage 0 (always runs)
    # --------------------------------------------------------------

    stage("STAGE 0 — SCOPE", "blue")
    stage0_scope(ctx)

    # --------------------------------------------------------------
    # Remaining enabled stages
    # --------------------------------------------------------------

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
    ) as progress:

        task = progress.add_task(
            f"Running profile: {profile_name}",
            total=len(enabled_stages),
        )

        for stage_number in enabled_stages:

            stage_func = _STAGE_FUNCTIONS.get(stage_number)

            if stage_func is None:
                continue

            stage_func(ctx)
            progress.advance(task)

    # --------------------------------------------------------------
    # Persist workflow state
    # --------------------------------------------------------------

    save_last_run(ctx)

    ok("Workflow completed ✅")

    summary_table(
        "ScopeForgeX Summary",
        [
            ("Profile", profile_name),
            ("Target Type", ctx.get("target_type", "-")),
            ("Target", ctx.get("target", "-")),
            ("Output Directory", ctx.get("outdir", "-")),
        ],
    )
