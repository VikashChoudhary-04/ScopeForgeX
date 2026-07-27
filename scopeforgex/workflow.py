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
* Runtime state management
* State persistence
* Summary generation

v0.5.3
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

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


_STAGE_FUNCTIONS: dict[int, Callable[[dict], object]] = {
    1: stage1_recon,
    2: stage2_enum,
    3: stage3_vuln,
    4: stage4_exploit,
    5: stage5_post,
    6: stage6_reporting,
}


_STAGE_NAMES = {
    0: "Scope",
    1: "Reconnaissance",
    2: "Enumeration",
    3: "Vulnerability Assessment",
    4: "Exploitation Preparation",
    5: "Post Assessment",
    6: "Reporting",
}


###############################################################################
# Workflow Engine
###############################################################################


class WorkflowEngine:
    """
    Executes ScopeForgeX workflows.
    """

    def __init__(
        self,
        profile_name: str,
    ) -> None:

        self.profile_name = profile_name

        self.profile = self._load_profile(
            profile_name,
        )

        self.enabled_stages = self.profile.get(
            "enabled_stages",
            [],
        )

        self.ctx = self._initialize_context()

        self.runtime = RuntimeState(
            profile=profile_name,
        )

        self.stage_results: list[StageResult] = []

        self.ctx["stage_results"] = self.stage_results
        self.ctx["tool_results"] = []


    ###########################################################################
    # Profile Loading
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


    ###########################################################################
    # Context
    ###########################################################################

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
        """
        Execute a single workflow stage.
        """

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

        success = True
        error_message = None


        try:

            result = stage_function(
                self.ctx
            )


            if result:

                if isinstance(
                    result,
                    list,
                ):

                    self.ctx[
                        "tool_results"
                    ].extend(
                        result
                    )


                self.runtime.metadata[
                    f"stage_{stage_number}_results"
                ] = result



        except Exception as exc:

            success = False

            error_message = str(
                exc
            )

            self.ctx[
                "workflow_error"
            ] = error_message

            self.ctx[
                "failed_stage"
            ] = stage_number


            warn(
                f"Stage {stage_number} failed: {exc}"
            )

            self.runtime.add_error(
                error_message
            )


        finished = datetime.now(
            timezone.utc
        )


        stage_result = StageResult(
            tool=_STAGE_NAMES.get(
                stage_number,
                f"Stage {stage_number}",
            ),
            capability=f"stage_{stage_number}",
            success=success,
            started_at=started,
            finished_at=finished,
            errors=(
                [error_message]
                if error_message
                else []
            ),
        )


        self.stage_results.append(
            stage_result
        )


        self.ctx[
            "stage_results"
        ] = self.stage_results


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
                    self.ctx
                )


                self.runtime.target = self.ctx.get(
                    "target",
                    "",
                )

                self.runtime.profile = (
                    self.profile_name
                )


                self.stage_results.append(
                    StageResult(
                        tool="Scope",
                        capability="stage_0",
                        success=True,
                        started_at=datetime.now(timezone.utc),
                        finished_at=datetime.now(timezone.utc),
                    )
                )


            except Exception as exc:

                self.ctx[
                    "workflow_error"
                ] = str(exc)

                warn(
                    f"Stage 0 failed: {exc}"
                )


            if self.ctx.get(
                "workflow_error"
            ):

                return


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
                        stage_number
                    )


                    progress.advance(
                        task
                    )


                    if self.ctx.get(
                        "workflow_error"
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


        self.ctx[
            "stage_results"
        ] = self.stage_results


        try:

            save_last_run(
                self.ctx
            )

        except Exception as exc:

            warn(
                f"Unable to save workflow state: {exc}"
            )


        failed = (
            "workflow_error"
            in self.ctx
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
                    "Output Directory",
                    self.ctx.get(
                        "outdir",
                        "-",
                    ),
                ),
                (
                    "Status",
                    "FAILED" if failed else "SUCCESS",
                ),
                (
                    "Elapsed",
                    f"{self.ctx['workflow_elapsed']:.2f}s",
                ),
            ],
        )


###############################################################################
# CLI Entry Point
###############################################################################


def run_profile(
    profile_name: str,
) -> None:

    engine = WorkflowEngine(
        profile_name
    )

    engine.execute()


__all__ = [
    "WorkflowEngine",
    "run_profile",
]
