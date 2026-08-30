"""
ScopeForgeX Workflow Engine
===========================

Capability-oriented workflow orchestration.

The workflow engine is responsible for:

- Loading assessment profiles
- Executing ScopeForgeX scope validation
- Selecting registered tools
- Resolving registered tool definitions to adapters
- Building canonical ToolContext instances
- Delegating adapter execution to the canonical ToolExecutor
- Executing tools in canonical phase order
- Preserving structured execution results
- Maintaining shared runtime context
- Running final reporting
- Building and storing the canonical workflow result
- Persisting workflow state

The workflow engine does NOT:

- Construct tool-specific commands
- Know individual tool CLI syntax
- Parse raw tool output
- Normalize findings
- Deduplicate findings
- Correlate findings
- Implement tool-specific logic

Those responsibilities belong to the registry, tool adapters, collectors,
finding engine and reporting layers.

Architecture
------------

USER
  ↓
SCOPEFORGEX CLI
  ↓
WORKFLOW ENGINE
  ↓
PROFILE
  ↓
TOOL SELECTION
  ↓
TOOL REGISTRY
  ↓
TOOL DEFINITION
  ↓
TOOL CONTEXT
  ↓
TOOL ADAPTER
  ↓
TOOL EXECUTOR
  ↓
EXECUTION RESULT
  ↓
RUNTIME STATE
  ↓
COLLECTORS / FINDING ENGINE
  ↓
CORRELATION / DEDUPLICATION
  ↓
REPORTING
  ↓
WORKFLOW RESULT

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.registry.tool_registry import (
    build_registry,
    create_tool_adapter,
)
from scopeforgex.runtime.enums import (
    AssessmentPhase,
    ExecutionStatus,
    get_phase_order,
)
from scopeforgex.runtime.results import StageResult
from scopeforgex.runtime.state import RuntimeState
from scopeforgex.runtime.tool_executor import ToolExecutor
from scopeforgex.state import save_last_run
from scopeforgex.ui import (
    info,
    ok,
    stage,
    summary_table,
    warn,
)
from scopeforgex.utils import load_yaml

from scopeforgex.stages.stage0_scope import stage0_scope
from scopeforgex.stages.stage6_report_cleanup import (
    stage6_report_cleanup,
)


###############################################################################
# Configuration
###############################################################################


PROFILE_FILE = "config/profiles.yaml"


###############################################################################
# Profile Helpers
###############################################################################


def _load_profiles() -> dict[str, Any]:
    """
    Load configured assessment profiles.
    """

    configuration = load_yaml(
        PROFILE_FILE,
    )

    if not isinstance(
        configuration,
        dict,
    ):
        raise SystemExit(
            f"Invalid profile configuration: {PROFILE_FILE}"
        )

    profiles = configuration.get(
        "profiles",
        {},
    )

    if not isinstance(
        profiles,
        dict,
    ):
        raise SystemExit(
            f"Invalid 'profiles' section in {PROFILE_FILE}"
        )

    return profiles


def _load_profile(
    profile_name: str,
) -> dict[str, Any]:
    """
    Load a single assessment profile.
    """

    profiles = _load_profiles()

    if profile_name not in profiles:
        available = ", ".join(
            sorted(
                profiles.keys()
            )
        )

        raise SystemExit(
            f"Unknown profile: {profile_name}. "
            f"Available profiles: {available}"
        )

    profile = profiles[
        profile_name
    ]

    if not isinstance(
        profile,
        dict,
    ):
        raise SystemExit(
            f"Invalid configuration for profile: "
            f"{profile_name}"
        )

    return profile


###############################################################################
# Tool Metadata Helpers
###############################################################################


def _tool_name(
    tool: Any,
) -> str:
    """
    Return a normalized tool name.
    """

    return str(
        getattr(
            tool,
            "name",
            "",
        )
    ).strip().lower()


def _tool_capability(
    tool: Any,
) -> str:
    """
    Return a normalized tool capability.
    """

    capability = getattr(
        tool,
        "capability",
        None,
    )

    if capability is None:
        definition = getattr(
            tool,
            "definition",
            None,
        )

        capability = getattr(
            definition,
            "capability",
            None,
        )

    if capability is None:
        return ""

    return str(
        getattr(
            capability,
            "value",
            capability,
        )
    ).strip().lower()


def _tool_requires_confirmation(
    tool: Any,
) -> bool:
    """
    Return whether a tool requires explicit confirmation.
    """

    value = getattr(
        tool,
        "requires_confirmation",
        False,
    )

    if callable(
        value
    ):
        try:
            return bool(
                value()
            )
        except TypeError:
            return False

    return bool(
        value
    )


def _tool_phase(
    tool: Any,
) -> AssessmentPhase | None:
    """
    Resolve a registry tool phase to AssessmentPhase.
    """

    value = getattr(
        tool,
        "phase",
        None,
    )

    if isinstance(
        value,
        AssessmentPhase,
    ):
        return value

    if hasattr(
        value,
        "value",
    ):
        value = value.value

    if value is None:
        return None

    try:
        return AssessmentPhase(
            str(value).strip().lower()
        )
    except ValueError:
        return None


###############################################################################
# Phase Configuration
###############################################################################


def _phase_sections() -> dict[
    AssessmentPhase,
    str,
]:
    """
    Return the canonical runtime-phase to profile-section mapping.
    """

    return {
        AssessmentPhase.RECONNAISSANCE: "reconnaissance",
        AssessmentPhase.ENUMERATION: "enumeration",
        AssessmentPhase.VULNERABILITY_ASSESSMENT: "vulnerability",
        AssessmentPhase.VULNERABILITY_VALIDATION: "validation",
        AssessmentPhase.CREDENTIAL_ASSESSMENT: "credential",
    }


###############################################################################
# Profile Tool Selection
###############################################################################


def _excluded_tools(
    profile: dict[str, Any],
) -> set[str]:
    """
    Return explicitly excluded tools.
    """

    excluded = profile.get(
        "excluded_tools",
        profile.get(
            "exclude_tools",
            [],
        ),
    )

    if not isinstance(
        excluded,
        list,
    ):
        raise SystemExit(
            "Profile 'excluded_tools' must be a list."
        )

    return {
        str(name).strip().lower()
        for name in excluded
        if str(name).strip()
    }


def _select_tools(
    profile: dict[str, Any],
) -> list[Any]:
    """
    Select canonical registry tool definitions according to the profile.

    The profile is authoritative.

    A tool is selected only when its profile configuration contains:

        enabled: true
    """

    registry = build_registry()

    excluded = _excluded_tools(
        profile
    )

    selected: list[Any] = []

    phase_sections = _phase_sections()

    for phase in get_phase_order():

        if phase in {
            AssessmentPhase.SCOPE_AUTHORIZATION,
            AssessmentPhase.REPORTING,
        }:
            continue

        section_name = phase_sections.get(
            phase
        )

        if section_name is None:
            continue

        section = profile.get(
            section_name,
            {},
        )

        if not isinstance(
            section,
            dict,
        ):
            raise SystemExit(
                f"Profile '{section_name}' section must be a mapping."
            )

        phase_tools = [
            tool
            for tool in registry.values()
            if _tool_phase(
                tool
            ) == phase
        ]

        for tool in phase_tools:

            name = _tool_name(
                tool
            )

            if not name:
                continue

            if name in excluded:
                continue

            lookup_name = (
                "testssl"
                if name == "testssl.sh"
                else name
            )

            configuration = section.get(
                lookup_name
            )

            if not isinstance(
                configuration,
                dict,
            ):
                continue

            if not bool(
                configuration.get(
                    "enabled",
                    False,
                )
            ):
                continue

            selected.append(
                tool
            )

    return selected


###############################################################################
# Tool Options
###############################################################################


def _tool_profile_options(
    profile: dict[str, Any],
    tool_name: str,
) -> dict[str, Any]:
    """
    Return profile-configured options for a tool.
    """

    options: dict[str, Any] = {}

    profile_tools = profile.get(
        "tool_options",
        {},
    )

    if isinstance(
        profile_tools,
        dict,
    ):
        configured = profile_tools.get(
            tool_name,
            {},
        )

        if isinstance(
            configured,
            dict,
        ):
            options.update(
                configured
            )

    section_names = (
        "reconnaissance",
        "enumeration",
        "vulnerability",
        "validation",
        "credential",
    )

    lookup_name = (
        "testssl"
        if tool_name == "testssl.sh"
        else tool_name
    )

    for section_name in section_names:

        section = profile.get(
            section_name,
            {},
        )

        if not isinstance(
            section,
            dict,
        ):
            continue

        configuration = section.get(
            lookup_name
        )

        if not isinstance(
            configuration,
            dict,
        ):
            continue

        configured_options = configuration.get(
            "options",
            {},
        )

        if isinstance(
            configured_options,
            dict,
        ):
            options.update(
                configured_options
            )

    return options


###############################################################################
# Tool Context
###############################################################################


def _create_tool_context(
    ctx: dict[str, Any],
    tool: Any,
    profile: dict[str, Any],
) -> ToolContext:
    """
    Build the typed ToolContext required by ToolAdapter implementations.

    Explicit workflow input_data takes precedence.

    Adapters declaring ``host_or_url_list`` as their canonical input type
    receive the workflow target automatically when no explicit input_data
    has been supplied. This allows pipeline-aware tools such as Nuclei to
    operate correctly during ordinary profile execution.
    """

    tool_name = _tool_name(
        tool
    )

    target = str(
        ctx.get(
            "target",
            "",
        )
    ).strip()

    outdir = ctx.get(
        "outdir"
    )

    if not outdir:
        raise ValueError(
            f"Tool '{tool_name}' requires a workflow output directory."
        )

    output_dir = (
        Path(
            str(outdir)
        )
        / "raw"
        / tool_name
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    phase_sections = _phase_sections()

    section_name = phase_sections.get(
        _tool_phase(
            tool
        )
    )

    configuration: dict[str, Any] = {}

    if section_name is not None:

        section = profile.get(
            section_name,
            {},
        )

        if isinstance(
            section,
            dict,
        ):
            lookup_name = (
                "testssl"
                if tool_name == "testssl.sh"
                else tool_name
            )

            configured = section.get(
                lookup_name
            )

            if isinstance(
                configured,
                dict,
            ):
                configuration = dict(
                    configured
                )

    configured_options = configuration.get(
        "options",
        {},
    )

    if not isinstance(
        configured_options,
        dict,
    ):
        configured_options = {}

    workflow_input = ctx.get(
        "input_data",
        (),
    )

    if workflow_input is None:
        workflow_input = ()

    if isinstance(
        workflow_input,
        str,
    ):
        workflow_input = (
            workflow_input,
        )

    explicit_input = tuple(
        str(value).strip()
        for value in workflow_input
        if value is not None
        and str(value).strip()
    )

    if explicit_input:
        input_data = explicit_input

    elif getattr(
        tool,
        "input_type",
        "",
    ) == "host_or_url_list":
        input_data = (
            target,
        )

    else:
        input_data = ()

    return ToolContext(
        target=target,
        output_dir=output_dir,
        profile=str(
            ctx.get(
                "profile",
                "standard",
            )
        ),
        options=dict(
            configured_options
        ),
        input_data=input_data,
    )


def _build_tool_context(
    ctx: dict[str, Any],
    tool: Any,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the generic execution context passed to ToolExecutor.
    """

    tool_ctx = dict(
        ctx
    )

    tool_name = _tool_name(
        tool
    )

    capability = _tool_capability(
        tool
    )

    phase_sections = _phase_sections()

    section_name = phase_sections.get(
        _tool_phase(
            tool
        )
    )

    configuration: dict[str, Any] = {}

    if section_name is not None:

        section = profile.get(
            section_name,
            {},
        )

        if isinstance(
            section,
            dict,
        ):
            lookup_name = (
                "testssl"
                if tool_name == "testssl.sh"
                else tool_name
            )

            configured = section.get(
                lookup_name
            )

            if isinstance(
                configured,
                dict,
            ):
                configuration = dict(
                    configured
                )

    configured_options = configuration.get(
        "options",
        {},
    )

    if not isinstance(
        configured_options,
        dict,
    ):
        configured_options = {}

    tool_ctx["tool"] = tool_name
    tool_ctx["capability"] = capability
    tool_ctx["tool_options"] = dict(
        configured_options
    )
    tool_ctx["options"] = dict(
        configured_options
    )
    tool_ctx["tool_configuration"] = configuration

    tool_ctx.setdefault(
        "timeout",
        600,
    )

    tool_ctx.setdefault(
        "tool_timeout",
        tool_ctx.get(
            "timeout",
            600,
        ),
    )

    return tool_ctx


###############################################################################
# Runtime Result Handling
###############################################################################


def _record_context_result(
    ctx: dict[str, Any],
    result: Any,
) -> None:
    """
    Preserve a structured execution result in shared workflow context.
    """

    results = ctx.get(
        "execution_results"
    )

    if not isinstance(
        results,
        list,
    ):
        results = []
        ctx[
            "execution_results"
        ] = results

    results.append(
        result
    )


def _record_phase_result(
    runtime: RuntimeState,
    phase: AssessmentPhase,
    results: list[Any],
) -> StageResult | None:
    """
    Record one completed assessment phase in RuntimeState.
    """

    if not results:
        return None

    statuses = {
        getattr(
            result,
            "status",
            None,
        )
        for result in results
    }

    if ExecutionStatus.FAILED.value in statuses:
        stage_status = ExecutionStatus.FAILED

    elif statuses and statuses <= {
        ExecutionStatus.SKIPPED.value,
    }:
        stage_status = ExecutionStatus.SKIPPED

    elif ExecutionStatus.SUCCESS.value in statuses:
        stage_status = ExecutionStatus.SUCCESS

    else:
        stage_status = ExecutionStatus.FAILED

    stage_result = StageResult(
        stage=f"phase:{phase.value}",
        phase=phase,
        status=stage_status,
        tool_results=list(
            results
        ),
    )

    stage_result.finalize()

    runtime.add_stage_result(
        stage_result
    )

    return stage_result


###############################################################################
# Workflow Engine
###############################################################################


class WorkflowEngine:
    """
    Capability-oriented ScopeForgeX workflow engine.
    """

    def __init__(
        self,
        profile_name: str,
    ) -> None:

        self.profile_name = (
            profile_name
        )

        self.profile = _load_profile(
            profile_name
        )

        self.selected_tools = _select_tools(
            self.profile
        )

        self.runtime = RuntimeState()

        self.runtime.profile = (
            self.profile_name
        )

        self.executor = ToolExecutor(
            runtime_state=self.runtime,
        )

        self.ctx: dict[str, Any] = {
            "profile": profile_name,
            "profile_config": self.profile,
            "runtime": self.runtime,
            "workflow_start_time": time.time(),
            "execution_results": [],
            "stage_results": [],
        }

    def _build_tool_context(
        self,
        ctx: dict[str, Any],
        tool: Any,
        profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build the generic execution context for a tool.
        """

        if profile is None:
            profile = self.profile

        return _build_tool_context(
            ctx,
            tool,
            profile,
        )

    def _create_tool_context(
        self,
        tool: Any,
        ctx: dict[str, Any],
        profile: dict[str, Any],
    ) -> ToolContext:
        """
        Create the canonical ToolContext for a registered tool.
        """

        return _create_tool_context(
            ctx,
            tool,
            profile,
        )

    def _prepare_context(
        self,
    ) -> None:

        self.runtime.profile = (
            self.profile_name
        )

        self.ctx["profile"] = (
            self.profile_name
        )

        self.ctx["profile_config"] = (
            self.profile
        )

        self.ctx["runtime"] = (
            self.runtime
        )

        if not isinstance(
            self.ctx.get(
                "execution_results"
            ),
            list,
        ):
            self.ctx[
                "execution_results"
            ] = []

        if not isinstance(
            self.ctx.get(
                "stage_results"
            ),
            list,
        ):
            self.ctx[
                "stage_results"
            ] = []

    def _sync_runtime_identity(
        self,
    ) -> None:

        self.runtime.profile = (
            self.profile_name
        )

        target = self.ctx.get(
            "target"
        )

        if target is not None:
            self.runtime.target = str(
                target
            )

    def _run_scope(
        self,
    ) -> None:

        stage(
            "PHASE 0 — SCOPE & AUTHORIZATION",
            "blue",
        )

        stage0_scope(
            self.ctx
        )

        self._sync_runtime_identity()

    def _execute_tool(
        self,
        tool: Any,
        ctx: dict[str, Any],
        profile: dict[str, Any],
    ) -> ExecutionResult:
        """
        Create and execute the canonical adapter for a registry tool.

        Registry:
            owns adapter construction.

        ToolContext:
            carries typed runtime configuration.

        ToolAdapter:
            owns command construction.

        ToolExecutor:
            owns process execution.
        """

        name = _tool_name(
            tool
        )

        capability = _tool_capability(
            tool
        )

        if not name:
            raise ValueError(
                "Selected tool definition has no valid name."
            )

        if not capability:
            raise ValueError(
                f"Tool '{name}' has no canonical capability metadata."
            )

        tool_context = _create_tool_context(
            ctx,
            tool,
            profile,
        )

        adapter = create_tool_adapter(
            name,
            context=tool_context,
        )

        execution_context = _build_tool_context(
            ctx,
            tool,
            profile,
        )

        return self.executor.execute(
            adapter,
            execution_context,
        )

    def _run_assessment_tools(
        self,
    ) -> None:

        if not self.selected_tools:
            warn(
                "No assessment tools are enabled "
                "for this profile."
            )
            return

        phase_groups: dict[
            AssessmentPhase,
            list[Any],
        ] = {
            phase: []
            for phase in get_phase_order()
        }

        for tool in self.selected_tools:

            phase = _tool_phase(
                tool
            )

            if phase is None:
                continue

            if phase not in phase_groups:
                continue

            phase_groups[
                phase
            ].append(
                tool
            )

        total_tools = len(
            self.selected_tools
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
                (
                    f"Running profile: "
                    f"{self.profile_name}"
                ),
                total=total_tools,
            )

            for phase in get_phase_order():

                if phase in {
                    AssessmentPhase.SCOPE_AUTHORIZATION,
                    AssessmentPhase.REPORTING,
                }:
                    continue

                tools = phase_groups.get(
                    phase,
                    [],
                )

                if not tools:
                    continue

                stage(
                    (
                        f"PHASE "
                        f"{phase.value.upper()}"
                    ),
                    "cyan",
                )

                phase_results: list[Any] = []

                for tool in tools:

                    name = _tool_name(
                        tool
                    )

                    capability = _tool_capability(
                        tool
                    )

                    info(
                        (
                            f"Executing "
                            f"{name} "
                            f"({capability or 'unknown'})"
                        )
                    )

                    if _tool_requires_confirmation(
                        tool
                    ):
                        info(
                            (
                                f"{name} requires "
                                "explicit authorization."
                            )
                        )

                    try:

                        result = self._execute_tool(
                            tool,
                            self.ctx,
                            self.profile,
                        )

                    except KeyboardInterrupt:

                        warn(
                            (
                                f"Execution interrupted "
                                f"while running {name}."
                            )
                        )

                        raise

                    except Exception as exc:

                        result = ExecutionResult.failure(
                            tool=name,
                            capability=(
                                capability
                                or "unknown"
                            ),
                            error=(
                                f"Tool execution failed: "
                                f"{type(exc).__name__}: "
                                f"{exc}"
                            ),
                        )

                    _record_context_result(
                        self.ctx,
                        result,
                    )

                    phase_results.append(
                        result
                    )

                    self.ctx[
                        "last_result"
                    ] = result

                    progress.advance(
                        task
                    )

                phase_result = (
                    _record_phase_result(
                        self.runtime,
                        phase,
                        phase_results,
                    )
                )

                if phase_result is not None:

                    self.ctx[
                        "last_stage_result"
                    ] = phase_result

                    stage_results = self.ctx.get(
                        "stage_results"
                    )

                    if not isinstance(
                        stage_results,
                        list,
                    ):
                        stage_results = []
                        self.ctx[
                            "stage_results"
                        ] = stage_results

                    stage_results.append(
                        phase_result
                    )

    def _run_reporting(
        self,
    ) -> None:

        stage(
            "PHASE 7 — REPORTING",
            "green",
        )

        self.ctx[
            "workflow_end_time"
        ] = time.time()

        self.ctx[
            "workflow_duration"
        ] = (
            self.ctx[
                "workflow_end_time"
            ]
            - self.ctx[
                "workflow_start_time"
            ]
        )

        self.ctx[
            "runtime"
        ] = self.runtime

        stage6_report_cleanup(
            self.ctx
        )

    def _finalize_runtime(
        self,
    ) -> None:

        self._sync_runtime_identity()

        if self.ctx.get(
            "workflow_end_time"
        ) is None:
            self.ctx[
                "workflow_end_time"
            ] = time.time()

        self.runtime.finish()

        self.ctx[
            "workflow_result"
        ] = self.runtime.finalize_workflow_result()

    def run(
        self,
    ) -> dict[str, Any]:

        self._prepare_context()

        self._run_scope()

        self._run_assessment_tools()

        self._run_reporting()

        self.ctx[
            "workflow_end_time"
        ] = time.time()

        self.ctx[
            "workflow_duration"
        ] = (
            self.ctx[
                "workflow_end_time"
            ]
            - self.ctx[
                "workflow_start_time"
            ]
        )

        self._finalize_runtime()

        return self.ctx


###############################################################################
# Public API
###############################################################################


def run_profile(
    profile_name: str,
) -> dict[str, Any]:
    """
    Execute a configured ScopeForgeX assessment profile.
    """

    engine = WorkflowEngine(
        profile_name
    )

    ctx = engine.run()

    try:
        save_last_run(
            ctx
        )
    except Exception as exc:
        warn(
            f"Could not persist last-run state: {exc}"
        )

    ok(
        "Workflow completed ✅"
    )

    summary_table(
        "ScopeForgeX Summary",
        [
            (
                "Profile",
                profile_name,
            ),
            (
                "Target Type",
                ctx.get(
                    "target_type",
                    "-",
                ),
            ),
            (
                "Target",
                ctx.get(
                    "target",
                    "-",
                ),
            ),
            (
                "Tools Executed",
                len(
                    engine.selected_tools
                ),
            ),
            (
                "Output Directory",
                ctx.get(
                    "outdir",
                    "-",
                ),
            ),
        ],
    )

    return ctx


__all__ = [
    "WorkflowEngine",
    "run_profile",
]
