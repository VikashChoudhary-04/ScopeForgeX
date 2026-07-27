"""
ScopeForgeX Workflow Engine
===========================

Workflow orchestration framework.

Responsibilities
----------------
* Profile loading
* Stage execution
* Runtime state management
* Workflow timing
* State persistence
* Summary generation

v0.5.0
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.runtime import (
    RuntimeState,
    StageResult,
    Status,
    WorkflowResult,
)

from scopeforgex.state import save_last_run

from scopeforgex.ui import (
    ok,
    stage,
    summary_table,
    warn,
)

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

_STAGE_FUNCTIONS = {
    1: stage1_recon,
    2: stage2_enum,
    3: stage3_vuln,
    4: stage4_exploit,
    5: stage5_post,
    6: stage6_reporting,
}


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

        self.profile = self._load_profile(
            profile_name,
        )

        self.enabled_stages = (
            self.profile.get(
                "enabled_stages",
                [],
            )
        )

        self.ctx = self._initialize_context()

        self.runtime = RuntimeState(
            profile=profile_name,
        )

        self.stage_results: list[StageResult] = []

    ###########################################################################
    # Internal Helpers
    ###########################################################################

    @staticmethod
    def _load_profile(
        profile_name: str,
    ) -> dict:

        profiles = load_yaml(
            "config/profiles.yaml",
        ).get(
            "profiles",
            {},
        )

        if profile_name not in profiles:
            raise SystemExit(
                f"Unknown profile: {profile_name}"
            )

        return profiles[profile_name]


    def _initialize_context(
        self,
    ) -> dict:

        return {
            "profile": self.profile_name,
            "workflow_start_time": time.time(),
        }


    ###########################################################################
    # Stage Execution
    ###########################################################################

    def execute_stage(
        self,
        stage_number: int,
    ) -> None:

        stage_function = _STAGE_FUNCTIONS.get(
            stage_number,
        )

        if stage_function is None:
            warn(
                f"Unknown stage: {stage_number}"
            )
            return


        started = datetime.now(
            timezone.utc,
        )

        start_time = time.time()


        try:

            stage_function(
                self.ctx,
            )

            success = True
            error = None


        except Exception as exc:

            success = False
            error = str(exc)

            self.ctx[
                "workflow_error"
            ] = error

            self.ctx[
                "failed_stage"
            ] = stage_number

            warn(
                f"Stage {stage_number} failed: {exc}"
            )


        finished = datetime.now(
            timezone.utc,
        )

        elapsed = (
            time.time()
            - start_time
        )


        result = StageResult(
            name=stage_function.__name__,
            status=(
                Status.COMPLETED
                if success
                else Status.FAILED
            ),
            started_at=started,
            finished_at=finished,
            elapsed=elapsed,
            stage=stage_number,
            metadata={
                "stage_number": stage_number,
                "error": error,
            },
        )


        self.stage_results.append(
            result
        )

        self.runtime.add_stage_result(
            result
        )


    ###########################################################################
    # Workflow Execution
    ###########################################################################

    def execute(
        self,
    ) -> None:

        try:

            stage(
                "STAGE 0 — SCOPE",
                "blue",
            )

            try:

                stage0_scope(
                    self.ctx,
                )

            except Exception as exc:

                self.ctx[
                    "workflow_error"
                ] = str(exc)

                warn(
                    f"Stage 0 failed: {exc}"
                )


            if not self.ctx.get(
                "workflow_error",
            ):

                with Progress(
                    SpinnerColumn(),
                    TextColumn(
                        "[progress.description]{task.description}"
                    ),
                    BarColumn(),
                    TimeElapsedColumn(),
                ) as progress:


                    task = progress.add_task(
                        (
                            f"Running profile: "
                            f"{self.profile_name}"
                        ),
                        total=len(
                            self.enabled_stages,
                        ),
                    )


                    for stage_number in self.enabled_stages:

                        self.execute_stage(
                            stage_number,
                        )

                        progress.advance(
                            task,
                        )

                        if self.ctx.get(
                            "workflow_error",
                        ):

                            warn(
                                "Workflow stopped "
                                f"after stage {stage_number}."
                            )

                            break


        finally:

            self.finish()


    ###########################################################################
    # Finalization
    ###########################################################################

    def finish(
        self,
    ) -> None:

        self.ctx[
            "workflow_end_time"
        ] = time.time()


        self.ctx[
            "workflow_elapsed"
        ] = (
            self.ctx[
                "workflow_end_time"
            ]
            -
            self.ctx[
                "workflow_start_time"
            ]
        )


        try:

            save_last_run(
                self.ctx,
            )

        except Exception as exc:

            warn(
                f"Unable to save workflow state: {exc}"
            )


        failed = bool(
            self.ctx.get(
                "workflow_error"
            )
        )


        self.runtime.finish()


        workflow_result = WorkflowResult(
            name="ScopeForgeX Workflow",
            status=(
                Status.FAILED
                if failed
                else Status.COMPLETED
            ),
            started_at=self.runtime.started_at,
            finished_at=datetime.now(
                timezone.utc,
            ),
            elapsed=self.ctx[
                "workflow_elapsed"
            ],
            workflow_id=str(
                self.runtime.workflow_id
            ),
            target=self.ctx.get(
                "target",
                "",
            ),
            profile=self.profile_name,
            stages=tuple(
                self.stage_results
            ),
        )


        self.runtime.set_workflow_result(
            workflow_result
        )


        if failed:

            warn(
                "Workflow completed with errors."
            )

        else:

            ok(
                "Workflow completed successfully ✅"
            )


        summary_table(
            "ScopeForgeX Summary",
            [
                (
                    "Profile",
                    self.profile_name,
                ),
                (
                    "Target",
                    self.ctx.get(
                        "target",
                        "-",
                    ),
                ),
                (
                    "Status",
                    (
                        "FAILED"
                        if failed
                        else "SUCCESS"
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
                        f"{self.ctx['workflow_elapsed']:.2f}s"
                    ),
                ),
            ],
        )


    @property
    def successful_stages(
        self,
    ) -> int:

        return sum(
            1
            for result in self.stage_results
            if result.successful
        )


    @property
    def failed_stages(
        self,
    ) -> int:

        return (
            len(self.stage_results)
            -
            self.successful_stages
        )


    @property
    def total_stage_time(
        self,
    ) -> float:

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
    Backward-compatible CLI entry point.
    """

    engine = WorkflowEngine(
        profile_name,
    )

    engine.execute()


__all__ = [
    "WorkflowEngine",
    "StageResult",
    "run_profile",
]
