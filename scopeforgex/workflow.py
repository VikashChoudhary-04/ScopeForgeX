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

v0.4.x
"""

from __future__ import annotations

import time
from dataclasses import dataclass
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
    Runtime information for an executed stage.
    """

    number: int
    name: str
    started: float
    finished: float | None = None
    success: bool = False
    error: str | None = None

    @property
    def elapsed(self) -> float:
        """
        Return the elapsed execution time.
        """

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

        self.stage_results: list[
            StageResult
        ] = []

    ###########################################################################
    # Internal Helpers
    ###########################################################################

    @staticmethod
    def _load_profile(
        profile_name: str,
    ) -> dict:
        """
        Load and validate the selected profile.
        """

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

        return profiles[
            profile_name
        ]

    def _initialize_context(
        self,
    ) -> dict:
        """
        Build the initial workflow context.
        """

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

        stage_function = (
            _STAGE_FUNCTIONS.get(
                stage_number,
            )
        )

        if stage_function is None:

            warn(
                f"Unknown stage: {stage_number}"
            )

            return

        result = StageResult(
            number=stage_number,
            name=stage_function.__name__,
            started=time.time(),
        )

        try:

            stage_function(
                self.ctx,
            )

            result.success = True

        except Exception as exc:

            result.error = str(exc)

            self.ctx[
                "workflow_error"
            ] = str(exc)

            self.ctx[
                "failed_stage"
            ] = stage_number

            warn(
                f"Stage {stage_number} "
                f"failed: {exc}"
            )

        finally:

            result.finished = time.time()

            self.stage_results.append(
                result,
            )
###############################################################################
# Workflow Execution
###############################################################################

    def execute(
        self,
    ) -> None:
        """
        Execute the complete workflow.
        """

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
                                f"after stage "
                                f"{stage_number}."
                            )

                            break

        finally:

            self.finish()
    def finish(
        self,
    ) -> None:
        """
        Finalize the workflow.

        Records timing information, persists workflow state,
        and displays the final execution summary.
        """

        self.ctx[
            "workflow_end_time"
        ] = time.time()

        self.ctx[
            "workflow_elapsed"
        ] = (
            self.ctx[
                "workflow_end_time"
            ]
            - self.ctx[
                "workflow_start_time"
            ]
        )

        #######################################################################
        # Persist Workflow State
        #######################################################################

        try:

            save_last_run(
                self.ctx,
            )

        except Exception as exc:

            warn(
                f"Unable to save workflow state: {exc}"
            )

        #######################################################################
        # Workflow Status
        #######################################################################

        workflow_failed = (
            "workflow_error"
            in self.ctx
        )

        if workflow_failed:

            warn(
                "Workflow completed with errors."
            )

        else:

            ok(
                "Workflow completed successfully ✅"
            )

        #######################################################################
        # Summary
        #######################################################################

        failed_stage = self.ctx.get(
            "failed_stage",
            "-",
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
                    "Workflow Status",
                    (
                        "FAILED"
                        if workflow_failed
                        else "SUCCESS"
                    ),
                ),
                (
                    "Successful Stages",
                    str(
                        self.successful_stages
                    ),
                ),
                (
                    "Failed Stages",
                    str(
                        len(
                            self.stage_results
                        )
                        - self.successful_stages
                    ),
                ),
                (
                    "Failed Stage",
                    str(
                        failed_stage
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

    ###########################################################################
    # Properties
    ###########################################################################

    @property
    def successful_stages(
        self,
    ) -> int:
        """
        Return the number of successful stages.
        """

        return sum(
            result.success
            for result
            in self.stage_results
        )

    @property
    def failed_stages(
        self,
    ) -> int:
        """
        Return the number of failed stages.
        """

        return (
            len(
                self.stage_results
            )
            - self.successful_stages
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
            for result
            in self.stage_results
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


###############################################################################
# Module Exports
###############################################################################

__all__ = [
    "WorkflowEngine",
    "StageResult",
    "run_profile",
]
