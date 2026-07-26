"""
workflow.py (reporting changes)

Only the reporting-related changes are shown below. Integrate these into your
existing workflow implementation.
"""

import time


def run_workflow(ctx):
    # ------------------------------------------------------------------
    # Record workflow start time once at the beginning.
    # ------------------------------------------------------------------
    ctx["workflow_start_time"] = time.time()

    # ==============================================================
    # Existing ScopeForgeX workflow stages...
    # ==============================================================
    #
    # stage1_scope(ctx)
    # stage2_recon(ctx)
    # stage3_validation(ctx)
    # stage4_vulnerability(ctx)
    # stage5_cleanup(ctx)
    #
    # (No changes required to those stages for this refactor.)
    #
    # ==============================================================

    # Final reporting stage
    stage6_reporting(ctx)
