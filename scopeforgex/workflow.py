"""
ScopeForgeX Workflow Engine
===========================

Capability-oriented workflow orchestration.

The workflow engine is responsible for:

- Loading assessment profiles
- Executing ScopeForgeX scope validation
- Selecting registered tools
- Resolving registered tool definitions to adapters
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
TOOL ADAPTER
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

v1.1.0
"""

from __future__ import annotations

import time
from typing import Any

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_registry import (
    build_registry,
    create_tool_adapter,
)
from scopeforgex.runtime.enums import (
    AssessmentPhase,
    get_phase_order,
)
from scopeforgex.runtime.results import StageResult
from scopeforgex.runtime.state import RuntimeState
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
from scopeforgex.stages.stage6_report_cleanup import stage6_reporting


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

    Returns:
        Dictionary containing configured profiles.
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

    Args:
        profile_name:
            Profile identifier.

    Returns:
        Profile configuration.
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

    Tool definitions are the canonical source for registry-level capability
    metadata. Older adapters may not expose capability directly.
    """

    return str(
        getattr(
            tool,
            "capability",
            "",
        )
    ).strip().lower()


def _tool_enabled_by_default(
    tool: Any,
) -> bool:
    """
    Return whether a tool is enabled by default.
    """

    return bool(
        getattr(
            tool,
            "enabled_by_default",
            True,
        )
    )


def _tool_requires_confirmation(
    tool: Any,
) -> bool:
    """
    Return whether a tool requires explicit confirmation.
    """

    return bool(
        getattr(
            tool,
            "requires_confirmation",
            False,
        )
    )


###############################################################################
# Profile Tool Selection
###############################################################################


def _configured_tool_names(
    profile: dict[str, Any],
) -> set[str] | None:
    """
    Return explicitly configured tool names.

    Supported profile keys:

    tools:
        List of enabled tool names.

    enabled_tools:
        Backward-compatible alias for tools.

    If neither key exists, None is returned and the workflow falls back
    to each tool's enabled_by_default setting.
    """

    configured = profile.get(
        "tools",
        profile.get(
            "enabled_tools"
        ),
    )

    if configured is None:
        return None

    if not isinstance(
        configured,
        list,
    ):
        raise SystemExit(
            "Profile 'tools' must be a list."
        )

    return {
        str(name).strip().lower()
        for name in configured
        if str(name).strip()
    }


def _configured_capabilities(
    profile: dict[str, Any],
) -> set[str] | None:
    """
    Return explicitly configured capabilities.

    This allows profiles to select capabilities without coupling the
    workflow engine to a particular implementation.

    Example:

        capabilities:
          - attack_surface_discovery
          - network_service_discovery
          - http_service_probing
    """

    configured = profile.get(
        "capabilities"
    )

    if configured is None:
        return None

    if not isinstance(
        configured,
        list,
    ):
        raise SystemExit(
            "Profile 'capabilities' must be a list."
        )

    return {
        str(capability).strip().lower()
        for capability in configured
        if str(capability).strip()
    }


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
    Select registered tool definitions according to the assessment profile.

    Selection precedence:

    1. Explicit tool selection
    2. Explicit capability selection
    3. Tool enabled_by_default metadata

    Exclusions always take precedence.

    Tools are returned in canonical AssessmentPhase order and registry
    order within each phase.

    The registry definitions remain authoritative here. Adapter resolution
    occurs only when a selected tool is executed.
    """

    registry = build_registry()

    configured_names = _configured_tool_names(
        profile
    )

    configured_capabilities = (
        _configured_capabilities(
            profile
        )
    )

    excluded = _excluded_tools(
        profile
    )

    selected: list[Any] = []

    for phase in get_phase_order():

        if phase in {
            AssessmentPhase.SCOPE,
            AssessmentPhase.REPORTING,
        }:
            continue

        phase_tools = registry.by_phase(
            phase
        )

        for tool in phase_tools:

            name = _tool_name(
                tool
            )

            capability = _tool_capability(
                tool
            )

            if not name:
                continue

            if name in excluded:
                continue

            if (
                configured_names is not None
                and name not in configured_names
            ):
                continue

            if (
                configured_names is None
                and configured_capabilities is not None
                and capability
                not in configured_capabilities
            ):
                continue

            if (
                configured_names is None
                and configured_capabilities is None
                and not _tool_enabled_by_default(
                    tool
                )
            ):
                continue

            selected.append(
                tool
            )

    registry_order = {
        id(tool): index
        for index, tool in enumerate(
            registry.all()
        )
    }

    selected.sort(
        key=lambda tool: registry_order.get(
            id(tool),
            999999,
        )
    )

    return selected


###############################################################################
# Tool Context
###############################################################################


def _build_tool_context(
    ctx: dict[str, Any],
    tool: Any,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the execution context passed to a tool adapter.

    The workflow engine supplies generic runtime information only.

    Tool-specific command construction remains the responsibility of the
    adapter.

    The returned context contains:

    - Existing workflow context
    - Tool name
    - Tool capability
    - Profile-specific tool options
    - Generic options alias for adapter compatibility
    """

    tool_ctx = dict(
        ctx
    )

    tool_name = _tool_name(
        tool
    )

    tool_options: dict[str, Any] = {}

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
            tool_options.update(
                configured
            )

    tool_ctx["tool"] = tool_name

    tool_ctx["capability"] = (
        _tool_capability(
            tool
        )
    )

    tool_ctx["tool_options"] = (
        tool_options
    )

    tool_ctx["options"] = (
        tool_options
    )

    return tool_ctx


###############################################################################
# Runtime Result Handling
###############################################################################


def _record_result(
    runtime: RuntimeState,
    result: Any,
) -> None:
    """
    Store a structured tool result in RuntimeState.

    RuntimeState is the authoritative runtime state container.
    """

    add_result = getattr(
        runtime,
        "add_tool_result",
        None,
    )

    if callable(
        add_result
    ):
        add_result(
            result
        )
        return

    add_result = getattr(
        runtime,
        "add_result",
        None,
    )

    if callable(
        add_result
    ):
        add_result(
            result
        )
        return

    if hasattr(
        runtime,
        "tool_results",
    ):
        runtime.tool_results.append(
            result
        )


def _record_context_result(
    ctx: dict[str, Any],
    result: Any,
) -> None:
    """
    Preserve a structured execution result in the shared workflow context.

    RuntimeState remains the authoritative runtime container. This context
    mirror exists so reporting and later workflow components can consume the
    actual ExecutionResult objects without having to know RuntimeState's
    internal storage implementation.
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
    Record the completed assessment phase in RuntimeState.

    RuntimeState is the authoritative source of workflow phase execution
    history.

    A phase result is recorded only when the phase contains selected tools.

    The phase succeeds only when every tool executed during the phase
    reports success.
    """

    if not results:
        return None

    success = all(
        bool(
            getattr(
                result,
                "success",
                False,
            )
        )
        for result in results
    )

    stage_result = StageResult(
        tool=f"phase:{phase.value}",
        capability="assessment_phase",
        success=success,
        phase=phase,
    )

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
        """
        Initialize the workflow engine.
        """

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

        self.ctx: dict[str, Any] = {
            "profile": profile_name,
            "profile_config": self.profile,
            "runtime": self.runtime,
            "workflow_start_time": time.time(),

            # Canonical execution history exposed to downstream workflow
            # components and reporting.
            "execution_results": [],

            # Phase-level execution history exposed to downstream consumers.
            "stage_results": [],
        }

    def _build_tool_context(
        self,
        ctx: dict[str, Any],
        tool: Any,
        profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build the execution context for a registered tool definition.

        This class-level wrapper delegates to the canonical module-level
        context builder.

        Args:
            ctx:
                Generic workflow context.

            tool:
                Registered tool definition.

            profile:
                Assessment profile configuration. When omitted, the engine's
                currently loaded profile is used.

        Returns:
            Tool execution context containing generic runtime data,
            tool identity and profile-configured options.
        """

        if profile is None:
            profile = self.profile

        return _build_tool_context(
            ctx,
            tool,
            profile,
        )

    def _prepare_context(
        self,
    ) -> None:
        """
        Prepare generic workflow context.

        Target information may be populated by the CLI or by the scope
        validation phase.
        """

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

        # Ensure downstream consumers always receive concrete containers.
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
        """
        Synchronize workflow identity from the shared context into RuntimeState.

        Scope validation may populate target information after RuntimeState
        initialization. RuntimeState must therefore receive the final target
        before the canonical WorkflowResult is constructed.
        """

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
        """
        Execute ScopeForgeX-native scope and authorization validation.

        Scope is not represented as an external tool.
        """

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
    ) -> Any:
        """
        Resolve a registered tool definition to its adapter and execute it.

        The workflow engine operates on ToolDefinition objects during
        selection and ordering. The registry is responsible for resolving
        the definition to the executable ToolBase adapter.

        The workflow engine never constructs tool-specific commands.
        """

        name = _tool_name(
            tool
        )

        adapter = getattr(
            tool,
            "adapter",
            None,
        )

        if adapter is None:
            return ExecutionResult.failure(
                tool=name,
                capability=_tool_capability(
                    tool
                ),
                error=(
                    f"Tool '{name}' is registered but "
                    "has no adapter."
                ),
            )

        instance = create_tool_adapter(
            name
        )

        tool_ctx = self._build_tool_context(
            ctx,
            tool,
            profile,
        )

        return instance.run(
            tool_ctx
        )

    def _run_assessment_tools(
        self,
    ) -> None:
        """
        Execute selected tools in canonical assessment phase order.

        Each completed assessment phase produces one canonical StageResult
        in RuntimeState.

        Each tool execution is preserved in both RuntimeState and the shared
        workflow context before the next tool or reporting phase executes.
        """

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

            phase = getattr(
                tool,
                "phase",
                None,
            )

            if phase in phase_groups:
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
                    AssessmentPhase.SCOPE,
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

                    capability = (
                        _tool_capability(
                            tool
                        )
                    )

                    info(
                        (
                            f"Executing "
                            f"{name} "
                            f"({capability})"
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

                    execution_start = time.time()

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

                        result = (
                            ExecutionResult.failure(
                                tool=name,
                                capability=capability,
                                error=(
                                    f"Tool execution "
                                    f"failed: {exc}"
                                ),
                            )
                        )

                    execution_end = time.time()

                    # Preserve execution timing without changing the
                    # ExecutionResult model contract. Existing metadata is
                    # retained and augmented when available.
                    metadata = getattr(
                        result,
                        "metadata",
                        None,
                    )

                    if isinstance(
                        metadata,
                        dict,
                    ):
                        metadata.setdefault(
                            "workflow_duration",
                            execution_end
                            - execution_start,
                        )

                        metadata.setdefault(
                            "workflow_profile",
                            self.profile_name,
                        )

                        metadata.setdefault(
                            "workflow_phase",
                            getattr(
                                phase,
                                "value",
                                str(phase),
                            ),
                        )

                    # RuntimeState remains authoritative.
                    _record_result(
                        self.runtime,
                        result,
                    )

                    # Explicit context-level execution history gives
                    # reporting a stable interface to the exact results
                    # produced by adapters.
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
        """
        Execute the ScopeForgeX-native reporting phase.

        Reporting receives the complete runtime context and structured
        execution history.

        Reporting is deliberately executed before RuntimeState is finalized
        so the reporting layer can consume the complete execution history
        while the workflow is still active.
        """

        stage(
            "PHASE 6 — REPORTING",
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

        # Make the authoritative runtime object and explicit execution
        # history available to the reporting layer.
        self.ctx[
            "runtime"
        ] = self.runtime

        stage6_reporting(
            self.ctx
        )

    def _finalize_runtime(
        self,
    ) -> None:
        """
        Finalize RuntimeState and construct the canonical WorkflowResult.

        RuntimeState becomes the authoritative aggregate of the complete
        workflow lifecycle before the final context is returned.
        """

        self._sync_runtime_identity()

        workflow_end_time = self.ctx.get(
            "workflow_end_time"
        )

        if workflow_end_time is None:
            workflow_end_time = time.time()

            self.ctx[
                "workflow_end_time"
            ] = workflow_end_time

        self.runtime.finish()

        workflow_result = (
            self.runtime.finalize_workflow_result()
        )

        self.ctx[
            "workflow_result"
        ] = workflow_result

    def run(
        self,
    ) -> dict[str, Any]:
        """
        Execute the complete assessment workflow.

        Returns:
            Shared workflow context containing the canonical WorkflowResult.
        """

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

    Args:
        profile_name:
            Profile identifier, for example:
            fast, standard or full.

    Returns:
        Final workflow context.
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
