"""
ScopeForgeX Workflow Engine
===========================

Workflow orchestration framework.

Responsibilities
----------------
* Profile loading
* Stage execution
* RuntimeState management
* Workflow timing
* State persistence
* Summary generation

v0.5.0
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from uuid import uuid4
from typing import Callable

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.state import save_last_run

from scopeforgex.ui import (
    ok,
    stage,
    summary_table,
    warn,
)

from scopeforgex.utils import load_yaml

from scopeforgex.runtime import (
    RuntimeState,
    StageResult,
    WorkflowResult,
)

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


_STAGE_FUNCTIONS: dict[int, Callable[[dict], None]] = {
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

        self.ctx["runtime_state"] = self.runtime

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
            timezone.utc
        )

        result = StageResult(
            tool=stage_function.__name__,
            capability=f"stage_{stage_number}",
            success=False,
            started_at=started,
            finished_at=started,
            duration=0.0,
        )


        try:

            stage_function(
                self.ctx,
            )

            finished = datetime.now(
                timezone.utc
            )

            result.success = True
            result.finished_at = finished
            result.duration = (
                finished.timestamp()
                -
                started.timestamp()
            )


        except Exception as exc:

            finished = datetime.now(
                timezone.utc
            )

            result.finished_at = finished
            result.duration = (
                finished.timestamp()
                -
                started.timestamp()
            )

            result.errors.append(
                str(exc)
            )

            self.ctx[
                "workflow_error"
            ] = str(exc)

            self.ctx[
                "failed_stage"
            ] = stage_number

            warn(
                f"Stage {stage_number} failed: {exc}"
            )


        finally:

            self.stage_results.append(
                result,
            )

            self.runtime.add_stage_result(
                result,
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

                ################################################################
                # Preserve Stage-0 generated workflow context
                #
                # Stage 0 initializes:
                # - target
                # - target_type
                # - outdir
                # - pipeline paths
                #
                # Normalize these values for downstream stages.
                ################################################################

                self.ctx.update(
                    {
                        "target": self.ctx.get(
                            "target",
                        ),

                        "target_type": self.ctx.get(
                            "target_type",
                        ),

                        "outdir": self.ctx.get(
                            "outdir",
                        ),

                        "pipeline": self.ctx.get(
                            "pipeline",
                            {},
                        ),
                    }
                )

            except Exception as exc:

                self.ctx[
                    "workflow_error"
                ] = str(exc)

                self.ctx[
                    "failed_stage"
                ] = 0

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
                        f"Running profile: {self.profile_name}",
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
                                f"Workflow stopped after stage {stage_number}."
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
            self.ctx["workflow_end_time"]
            -
            self.ctx["workflow_start_time"]
        )


        try:

            workflow_failed = (
                "workflow_error"
                in self.ctx
            )


            workflow_result = WorkflowResult(
                tool="scopeforgex",
                capability="workflow",
                success=not workflow_failed,
                started_at=datetime.fromtimestamp(
                    self.ctx["workflow_start_time"],
                    tz=timezone.utc,
                ),
                finished_at=datetime.now(
                    timezone.utc,
                ),
                duration=self.ctx[
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
                workflow_result,
            )

            self.runtime.finish()


        except Exception as exc:

            warn(
                f"Unable to create workflow result: {exc}"
            )


        try:

            save_last_run(
                self.ctx,
            )

        except Exception as exc:

            warn(
                f"Unable to save workflow state: {exc}"
            )


        if "workflow_error" in self.ctx:

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
                        if "workflow_error"
                        in self.ctx
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
                    f"{self.ctx['workflow_elapsed']:.2f}s",
                ),
            ],
        )


    @property
    def successful_stages(
        self,
    ) -> int:

        return sum(
            result.success
            for result
            in self.stage_results
        )


    @property
    def failed_stages(
        self,
    ) -> int:

        return (
            len(
                self.stage_results
            )
            -
            self.successful_stages
        )


###############################################################################
# Public API
###############################################################################


def run_profile(
    profile_name: str,
) -> None:

    engine = WorkflowEngine(
        profile_name,
    )

    engine.execute()


__all__ = [
    "WorkflowEngine",
    "run_profile",
]
