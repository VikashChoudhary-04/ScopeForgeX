"""
ScopeForgeX Workflow Engine
===========================

Workflow orchestration framework.

Responsibilities
----------------
* Profile loading
* Stage execution
* Progress reporting
* Workflow timing
* State persistence
* Summary generation

v0.4.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

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

###############################################################################
# Stage Registry
###############################################################################

_STAGE_FUNCTIONS: dict[
    int,
    Callable[[dict], None],
] = {
    1: stage1_recon,
    2: stage2_enum,
    3: stage3_vuln,
    4: stage4_exploit,
    5: stage5_post,
    6: stage6_reporting,
}

###############################################################################
# Workflow Metadata
###############################################################################


@dataclass(slots=True)
class StageResult:
    """
    Runtime information for a stage.
    """

    number: int
    name: str
    started: float
    finished: float | None = None
    success: bool = False

    @property
    def elapsed(self) -> float:

        if self.finished is None:
            return 0.0

        return self.finished - self.started


###############################################################################
# Workflow Engine
###############################################################################


class WorkflowEngine:
    """
    Executes a ScopeForgeX profile.
    """

    def __init__(
        self,
        profile_name: str,
    ) -> None:

        self.profile_name = profile_name

        profiles = load_yaml(
            "config/profiles.yaml"
        ).get(
            "profiles",
            {},
        )

        if profile_name not in profiles:
            raise SystemExit(
                f"Unknown profile: {profile_name}"
            )

        self.profile = profiles[
            profile_name
        ]

        self.enabled_stages = (
            self.profile.get(
                "enabled_stages",
                [],
            )
        )

        self.ctx: dict = {
            "profile": profile_name,
            "workflow_start_time": time.time(),
        }

        self.stage_results: list[
            StageResult
        ] = []

    def execute_stage(
        self,
        stage_number: int,
    ) -> None:

        stage_function = (
            _STAGE_FUNCTIONS.get(
                stage_number
            )
        )

        if stage_function is None:
            return

        result = StageResult(
            number=stage_number,
            name=stage_function.__name__,
            started=time.time(),
        )

        stage_function(
            self.ctx
        )

        result.finished = time.time()
        result.success = True

        self.stage_results.append(
            result
        )
###############################################################################
# Workflow Execution
###############################################################################


    def execute(self) -> None:
        """
        Execute the complete workflow.
        """

        stage(
            "STAGE 0 — SCOPE",
            "blue",
        )

        stage0_scope(
            self.ctx,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn(
                "[progress.description]{task.description}"
            ),
            BarColumn(),
            TimeElapsedColumn(),
        ) as progress:

            task = progress.add_task(
                f"Running profile: {self.profile_name}",
                total=len(self.enabled_stages),
            )

            for stage_number in self.enabled_stages:

                self.execute_stage(
                    stage_number,
                )

                progress.advance(task)

        self.finish()

    def finish(self) -> None:
        """
        Persist workflow state and
        display the final summary.
        """

        self.ctx[
            "workflow_end_time"
        ] = time.time()

        self.ctx[
            "workflow_elapsed"
        ] = (
            self.ctx["workflow_end_time"]
            - self.ctx["workflow_start_time"]
        )

        save_last_run(
            self.ctx,
        )

        ok(
            "Workflow completed ✅"
        )

        summary_table(
            "ScopeForgeX Summary",
            [
                (
                    "Profile",
                    self.profile_name,
                ),
                (
                    "Target Type",
                    self.ctx.get(
                        "target_type",
                        "-",
                    ),
                ),
                (
                    "Target",
                    self.ctx.get(
                        "target",
                        "-",
                    ),
                ),
                (
                    "Output Directory",
                    self.ctx.get(
                        "outdir",
                        "-",
                    ),
                ),
                (
                    "Stages Executed",
                    str(
                        len(
                            self.stage_results
                        )
                    ),
                ),
                (
                    "Elapsed",
                    (
                        f"{self.ctx['workflow_elapsed']:.2f} s"
                    ),
                ),
            ],
        )

    @property
    def successful_stages(
        self,
    ) -> int:
        """
        Number of successfully completed stages.
        """

        return sum(
            result.success
            for result in self.stage_results
        )

    @property
    def total_stage_time(
        self,
    ) -> float:
        """
        Combined execution time for all stages.
        """

        return sum(
            result.elapsed
            for result in self.stage_results
        )
###############################################################################
# Public API
###############################################################################


def run_profile(
    profile_name: str,
) -> None:
    """
    Backward-compatible entry point used by the CLI.

    Executes the selected ScopeForgeX profile.
    """

    engine = WorkflowEngine(
        profile_name,
    )

    engine.execute()


###############################################################################
# Module Exports
###############################################################################

__all__ = [
    "WorkflowEngine",
    "StageResult",
    "run_profile",
]
