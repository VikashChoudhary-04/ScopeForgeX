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
- Maintaining assessment-wide collector and finding state
- Persisting assessment evidence references
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
COLLECTOR
  ↓
ANALYSIS PIPELINE
  ↓
NORMALIZED / DEDUPLICATED FINDINGS
  ↓
CORRELATION
  ↓
EVIDENCE MANAGER
  ↓
EVIDENCE STORE
  ↓
WORKFLOW CONTEXT
  ↓
REPORTING
  ↓
WORKFLOW RESULT

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import json
import time
from importlib.resources import as_file, files
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Mapping

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from scopeforgex.evidence.manager import (
    EvidenceManager,
)
from scopeforgex.findings.model import Finding
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
    assessment_context,
    assessment_summary,
    info,
    ok,
    stage,
    warn,
    workflow_tool_result,
    workflow_tool_start,
)
from scopeforgex.utils import load_yaml

from scopeforgex.stages.stage0_scope import stage0_scope
from scopeforgex.stages.stage6_report_cleanup import (
    stage6_report_cleanup,
)


###############################################################################
# Configuration
###############################################################################


PROFILE_RESOURCE = (
    files("scopeforgex")
    / "config"
    / "profiles.yaml"
)


###############################################################################
# Profile Helpers
###############################################################################


def _load_profiles() -> dict[str, Any]:
    """
    Load assessment profiles from the installed ScopeForgeX package.

    Package resources are resolved independently of the current working
    directory, allowing both source-tree and installed-wheel execution.
    """

    try:
        with as_file(
            PROFILE_RESOURCE
        ) as path:

            configuration = load_yaml(
                str(path)
            )

    except (
        FileNotFoundError,
        ModuleNotFoundError,
    ) as exc:

        raise SystemExit(
            "ScopeForgeX profile configuration could not be loaded: "
            f"{exc}"
        ) from exc

    if not isinstance(
        configuration,
        dict,
    ):
        raise SystemExit(
            "Invalid packaged profile configuration."
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
            "Invalid 'profiles' section in packaged configuration."
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
            "Invalid configuration for profile: "
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
            str(
                value
            ).strip().lower()
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
        AssessmentPhase.RECONNAISSANCE:
            "reconnaissance",

        AssessmentPhase.ENUMERATION:
            "enumeration",

        AssessmentPhase.VULNERABILITY_ASSESSMENT:
            "vulnerability",

        AssessmentPhase.VULNERABILITY_VALIDATION:
            "validation",

        AssessmentPhase.CREDENTIAL_ASSESSMENT:
            "credential",
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
# Observation Input Projection
###############################################################################


def _mapping_value(
    value: Any,
    key: str,
) -> Any:
    """Return a value from either a mapping or an object."""
    if isinstance(value, dict):
        return value.get(key)

    return getattr(
        value,
        key,
        None,
    )


def _absolute_http_url(
    value: Any,
) -> str | None:
    """
    Return an absolute HTTP(S) URL or None.

    Input projection is intentionally conservative. A downstream URL-based
    tool must never receive arbitrary observation values such as parameters,
    route fragments, severity labels or finding titles.
    """

    if value is None:
        return None

    candidate = str(
        value
    ).strip()

    if not candidate:
        return None

    try:
        parsed = urlparse(
            candidate
        )
    except ValueError:
        return None

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    if not parsed.netloc:
        return None

    return candidate


def _project_observation_inputs(
    tool: Any,
    observations: Any,
) -> tuple[str, ...]:
    """
    Project previously collected observations into the receiving tool's
    declared input type.

    This function is deliberately source-tool agnostic. It does not know
    whether an observation originated from Katana, JSLuice, Kiterunner,
    FFUF, Nmap or another collector.

    The receiving tool's canonical ``input_type`` determines what can be
    projected.
    """

    input_type = str(
        getattr(
            tool,
            "input_type",
            "",
        )
        or ""
    ).strip().lower()

    capability = str(
        getattr(
            tool,
            "capability",
            "",
        )
        or ""
    ).strip().lower()

    if input_type not in {
        "url",
        "host",
        "host_or_url_list",
    }:
        return ()

    if observations is None:
        return ()

    if isinstance(
        observations,
        (str, bytes),
    ):
        observations = (
            observations,
        )

    projected: list[str] = []
    seen: set[str] = set()

    url_observation_types = {
        "URL",
        "ENDPOINT",
        "JS_URL",
        "JS_ENDPOINT",
        "API_ENDPOINT",
        "API_REFERENCE",
        "HIDDEN_ENDPOINT",
    }

    javascript_capability = (
        capability
        == "javascript_attack_surface_analysis"
    )

    javascript_observation_types = {
        "JS_URL",
        "JS_ENDPOINT",
    }

    for observation in observations:
        candidate: str | None = None

        if input_type in {
            "url",
            "host_or_url_list",
        }:
            observation_type = str(
                _mapping_value(
                    observation,
                    "observation_type",
                )
                or ""
            ).strip().upper()

            if javascript_capability:
                if observation_type in javascript_observation_types:
                    pass
                elif observation_type == "RESOURCE":
                    metadata = _mapping_value(
                        observation,
                        "metadata",
                    )

                    if not isinstance(
                        metadata,
                        Mapping,
                    ):
                        continue

                    resource_type = str(
                        metadata.get(
                            "resource_type",
                            "",
                        )
                        or ""
                    ).strip().lower()

                    if resource_type != "javascript":
                        continue
                else:
                    continue
            elif observation_type not in url_observation_types:
                continue

            candidate = _absolute_http_url(
                _mapping_value(
                    observation,
                    "url",
                )
            )

            if candidate is None:
                candidate = _absolute_http_url(
                    _mapping_value(
                        observation,
                        "value",
                    )
                )

        elif input_type == "host":
            value = _mapping_value(
                observation,
                "host",
            )

            if value is not None:
                candidate = str(
                    value
                ).strip() or None

        if not candidate:
            continue

        if candidate in seen:
            continue

        seen.add(candidate)
        projected.append(candidate)

    return tuple(
        projected
    )


def _prepare_tool_input_data(
    ctx: dict[str, Any],
    tool: Any,
    executor: ToolExecutor,
) -> None:
    """
    Prepare canonical input_data for the next tool.

    Previously collected normalized observations are projected according to
    the receiving tool's declared input type.

    If no compatible discovered inputs exist, the existing workflow input is
    preserved. This guarantees that the original assessment target remains
    the fallback and that observation projection never silently changes the
    target of an otherwise independent tool.
    """

    projected = _project_observation_inputs(
        tool,
        executor.last_collector_observations,
    )

    if projected:
        ctx["input_data"] = projected



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
    has been supplied.
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

    The context intentionally retains references to the workflow-owned
    assessment collections so ToolExecutor can update the canonical state
    without creating a second workflow-level finding engine.
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


def _sync_executor_state(
    ctx: dict[str, Any],
    executor: ToolExecutor,
) -> None:
    """
    Synchronize assessment-wide executor state into workflow context.

    ToolExecutor remains the owner of collection and finding processing.
    WorkflowEngine only exposes the resulting state to downstream stages.

    The workflow-owned containers are updated in place so any shallow
    execution contexts created from ``ctx`` continue to reference the same
    collections.
    """

    collector_results = ctx.get(
        "collector_results"
    )

    if not isinstance(
        collector_results,
        list,
    ):

        collector_results = []

        ctx[
            "collector_results"
        ] = collector_results

    collector_results.clear()

    collector_results.extend(
        executor.collector_results
    )

    native_analyzer_results = ctx.get(
        "native_analyzer_results"
    )

    if not isinstance(
        native_analyzer_results,
        list,
    ):

        native_analyzer_results = []

        ctx[
            "native_analyzer_results"
        ] = native_analyzer_results

    native_analyzer_results.clear()

    native_analyzer_results.extend(
        executor.native_analyzer_results
    )

    vulnerability_intelligence_results = ctx.get(
        "vulnerability_intelligence_results"
    )

    if not isinstance(
        vulnerability_intelligence_results,
        list,
    ):

        vulnerability_intelligence_results = []

        ctx[
            "vulnerability_intelligence_results"
        ] = vulnerability_intelligence_results

    vulnerability_intelligence_results.clear()

    vulnerability_intelligence_results.extend(
        executor.vulnerability_intelligence_results
    )

    software_assessments = ctx.get(
        "software_assessments"
    )

    if not isinstance(
        software_assessments,
        list,
    ):

        software_assessments = []

        ctx[
            "software_assessments"
        ] = software_assessments

    software_assessments.clear()

    software_assessments.extend(
        executor.software_assessments
    )

    findings = ctx.get(
        "findings"
    )

    if not isinstance(
        findings,
        list,
    ):

        findings = []

        ctx[
            "findings"
        ] = findings

    findings.clear()

    findings.extend(
        executor.findings
    )

    correlation_groups = ctx.get(
        "correlation_groups"
    )

    if not isinstance(
        correlation_groups,
        list,
    ):

        correlation_groups = []

        ctx[
            "correlation_groups"
        ] = correlation_groups

    correlation_groups.clear()

    correlation_groups.extend(
        executor.correlation_groups
    )

    correlated_findings = ctx.get(
        "correlated_findings"
    )

    if not isinstance(
        correlated_findings,
        list,
    ):

        correlated_findings = []

        ctx[
            "correlated_findings"
        ] = correlated_findings

    correlated_findings.clear()

    correlated_findings.extend(
        executor.findings
    )

    analysis_result = executor.analysis_result

    analysis_context = ctx.get(
        "analysis_result"
    )

    if not isinstance(
        analysis_context,
        dict,
    ):

        analysis_context = {}

        ctx[
            "analysis_result"
        ] = analysis_context

    analysis_context.clear()

    if analysis_result is not None:

        as_dict = getattr(
            analysis_result,
            "as_dict",
            None,
        )

        if callable(
            as_dict
        ):

            try:

                serialized = as_dict()

                if isinstance(
                    serialized,
                    dict,
                ):
                    analysis_context.update(
                        serialized
                    )

            except Exception:
                pass

        if not analysis_context:

            for key in (
                "input_count",
                "finding_count",
                "duplicate_count",
                "error_count",
                "errors",
                "metadata",
            ):

                if hasattr(
                    analysis_result,
                    key,
                ):
                    analysis_context[
                        key
                    ] = getattr(
                        analysis_result,
                        key,
                    )

    analysis_context[
        "findings"
    ] = [
        finding.as_dict()
        if hasattr(
            finding,
            "as_dict",
        )
        else finding
        for finding in executor.findings
    ]

    analysis_context[
        "correlation_groups"
    ] = [
        group.as_dict()
        if hasattr(
            group,
            "as_dict",
        )
        else group
        for group in executor.correlation_groups
    ]

    ctx[
        "analysis"
    ] = analysis_context


###############################################################################
# Evidence Handling
###############################################################################


def _reference_dict(
    reference: Any,
) -> dict[str, Any] | None:
    """
    Convert an EvidenceReference-like object into a report-safe dictionary.
    """

    if reference is None:
        return None

    as_dict = getattr(
        reference,
        "as_dict",
        None,
    )

    if callable(
        as_dict
    ):

        try:

            serialized = as_dict()

            if isinstance(
                serialized,
                dict,
            ):
                return serialized

        except Exception:
            return None

    if isinstance(
        reference,
        dict,
    ):
        return dict(
            reference
        )

    return None


def _append_unique_reference(
    references: list[dict[str, Any]],
    reference: Any,
) -> None:
    """
    Append an evidence reference once.
    """

    serialized = _reference_dict(
        reference
    )

    if not serialized:
        return

    evidence_id = str(
        serialized.get(
            "evidence_id",
            "",
        )
    ).strip()

    if not evidence_id:
        return

    existing = {
        str(
            item.get(
                "evidence_id",
                "",
            )
        ).strip()
        for item in references
        if isinstance(
            item,
            dict,
        )
    }

    if evidence_id not in existing:
        references.append(
            serialized
        )


def _evidence_raw_filename(
    result: ExecutionResult,
    stream: str,
) -> str:
    """
    Return a deterministic raw-evidence filename for one execution stream.
    """

    tool = _tool_name(
        result
    ) or "tool"

    return (
        f"{tool}_{stream}.txt"
    )


def _serialize_raw_execution(
    result: ExecutionResult,
) -> str:
    """
    Serialize execution metadata without embedding raw stdout/stderr.

    This helper is retained for metadata associated with raw evidence.
    """

    payload = {
        "tool": result.tool,
        "capability": result.capability,
        "status": result.status,
        "success": result.success,
        "artifacts": list(
            result.artifacts
        ),
        "warnings": list(
            result.warnings
        ),
        "errors": list(
            result.errors
        ),
        "started_at": result.started_at.isoformat(),
        "finished_at": (
            result.finished_at.isoformat()
            if result.finished_at is not None
            else None
        ),
        "duration": result.duration,
    }

    return json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def _persist_execution_evidence(
    ctx: dict[str, Any],
    result: ExecutionResult,
) -> None:
    """
    Persist raw execution evidence through the canonical EvidenceManager.

    stdout and stderr are stored separately so their original contents remain
    intact. Only lightweight EvidenceReference dictionaries are placed into
    the workflow context.
    """

    manager = ctx.get(
        "evidence_manager"
    )

    if not isinstance(
        manager,
        EvidenceManager,
    ):
        return

    references = ctx.get(
        "raw_evidence_references"
    )

    if not isinstance(
        references,
        list,
    ):

        references = []

        ctx[
            "raw_evidence_references"
        ] = references

    target = str(
        ctx.get(
            "target",
            "",
        )
    ).strip() or None

    metadata = {
        "run_id": str(
            ctx.get(
                "run_id",
                "",
            )
        ).strip(),
        "capability": result.capability,
        "execution_status": result.status,
        "success": result.success,
    }

    if result.artifacts:
        metadata[
            "execution_artifacts"
        ] = list(
            result.artifacts
        )

    streams = (
        (
            "stdout",
            result.stdout,
        ),
        (
            "stderr",
            result.stderr,
        ),
    )

    for stream_name, content in streams:

        if not content:
            continue

        try:

            reference = manager.store_raw(
                result.tool,
                content,
                target=target,
                filename=_evidence_raw_filename(
                    result,
                    stream_name,
                ),
                metadata={
                    **metadata,
                    "stream": stream_name,
                },
            )

            _append_unique_reference(
                references,
                reference,
            )

        except Exception as exc:

            warnings = ctx.get(
                "warnings"
            )

            if not isinstance(
                warnings,
                list,
            ):

                warnings = []

                ctx[
                    "warnings"
                ] = warnings

            warnings.append(
                (
                    "Could not persist raw evidence for "
                    f"{result.tool} ({stream_name}): "
                    f"{type(exc).__name__}: {exc}"
                )
            )


def _persist_finding_evidence(
    ctx: dict[str, Any],
    findings: list[Any],
) -> None:
    """
    Persist actual Finding objects as normalized evidence.

    Observations and arbitrary collector objects are intentionally ignored.
    """

    manager = ctx.get(
        "evidence_manager"
    )

    if not isinstance(
        manager,
        EvidenceManager,
    ):
        return

    references = ctx.get(
        "finding_evidence_references"
    )

    if not isinstance(
        references,
        list,
    ):

        references = []

        ctx[
            "finding_evidence_references"
        ] = references

    persisted_ids = ctx.get(
        "_persisted_finding_evidence_ids"
    )

    if not isinstance(
        persisted_ids,
        set,
    ):

        persisted_ids = set()

        ctx[
            "_persisted_finding_evidence_ids"
        ] = persisted_ids

    raw_references = ctx.get(
        "raw_evidence_references",
        [],
    )

    raw_by_tool: dict[str, list[str]] = {}

    if isinstance(
        raw_references,
        list,
    ):

        for reference in raw_references:

            if not isinstance(
                reference,
                dict,
            ):
                continue

            evidence_id = str(
                reference.get(
                    "evidence_id",
                    "",
                )
            ).strip()

            source_tool = str(
                reference.get(
                    "source_tool",
                    "",
                )
            ).strip().lower()

            if (
                evidence_id
                and source_tool
            ):
                raw_by_tool.setdefault(
                    source_tool,
                    [],
                ).append(
                    evidence_id
                )

    for finding in findings:

        if not isinstance(
            finding,
            Finding,
        ):
            continue

        finding_id = str(
            finding.finding_id
        ).strip()

        if not finding_id:
            continue

        if finding_id in persisted_ids:
            continue

        raw_ids = raw_by_tool.get(
            str(
                finding.source_tool or ""
            ).strip().lower(),
            [],
        )

        try:

            reference = manager.store_finding(
                finding,
                raw_evidence_id=(
                    raw_ids[0]
                    if raw_ids
                    else None
                ),
                metadata={
                    "run_id": str(
                        ctx.get(
                            "run_id",
                            "",
                        )
                    ).strip(),
                },
            )

            _append_unique_reference(
                references,
                reference,
            )

            persisted_ids.add(
                finding_id
            )

        except Exception as exc:

            warnings = ctx.get(
                "warnings"
            )

            if not isinstance(
                warnings,
                list,
            ):

                warnings = []

                ctx[
                    "warnings"
                ] = warnings

            warnings.append(
                (
                    "Could not persist finding evidence for "
                    f"{finding_id}: "
                    f"{type(exc).__name__}: {exc}"
                )
            )


def _persist_correlated_evidence(
    ctx: dict[str, Any],
    groups: list[Any],
) -> None:
    """
    Persist correlation groups as correlated evidence.

    Correlation objects are never converted into Findings.
    """

    manager = ctx.get(
        "evidence_manager"
    )

    if not isinstance(
        manager,
        EvidenceManager,
    ):
        return

    references = ctx.get(
        "correlated_evidence_references"
    )

    if not isinstance(
        references,
        list,
    ):

        references = []

        ctx[
            "correlated_evidence_references"
        ] = references

    persisted_ids = ctx.get(
        "_persisted_correlated_evidence_ids"
    )

    if not isinstance(
        persisted_ids,
        set,
    ):

        persisted_ids = set()

        ctx[
            "_persisted_correlated_evidence_ids"
        ] = persisted_ids

    pending: list[Any] = []

    for group in groups:

        if isinstance(
            group,
            dict,
        ):

            identifier = str(
                group.get(
                    "group_id",
                    "",
                )
            ).strip()

        else:

            identifier = str(
                getattr(
                    group,
                    "group_id",
                    "",
                )
                or ""
            ).strip()

        if identifier and identifier in persisted_ids:
            continue

        pending.append(
            group
        )

    if not pending:
        return

    try:

        stored = manager.store_correlated(
            pending,
            metadata={
                "run_id": str(
                    ctx.get(
                        "run_id",
                        "",
                    )
                ).strip(),
            },
        )

        for group, reference in zip(
            pending,
            stored,
        ):

            _append_unique_reference(
                references,
                reference,
            )

            if isinstance(
                group,
                dict,
            ):

                identifier = str(
                    group.get(
                        "group_id",
                        "",
                    )
                ).strip()

            else:

                identifier = str(
                    getattr(
                        group,
                        "group_id",
                        "",
                    )
                    or ""
                ).strip()

            if identifier:
                persisted_ids.add(
                    identifier
                )

    except Exception as exc:

        warnings = ctx.get(
            "warnings"
        )

        if not isinstance(
            warnings,
            list,
        ):

            warnings = []

            ctx[
                "warnings"
            ] = warnings

        warnings.append(
            (
                "Could not persist correlated evidence: "
                f"{type(exc).__name__}: {exc}"
            )
        )


def _persist_assessment_evidence(
    ctx: dict[str, Any],
    result: ExecutionResult | None = None,
) -> None:
    """
    Persist the current assessment evidence state.

    Raw execution evidence is persisted for the supplied result. Normalized
    findings and correlated groups are persisted from the executor state
    already synchronized into ``ctx``.
    """

    if result is not None:
        _persist_execution_evidence(
            ctx,
            result,
        )

    findings = ctx.get(
        "findings",
        [],
    )

    if isinstance(
        findings,
        list,
    ):
        _persist_finding_evidence(
            ctx,
            findings,
        )

    groups = ctx.get(
        "correlation_groups",
        [],
    )

    if isinstance(
        groups,
        list,
    ):
        _persist_correlated_evidence(
            ctx,
            groups,
        )

    raw_references = ctx.get(
        "raw_evidence_references"
    )

    if not isinstance(
        raw_references,
        list,
    ):
        raw_references = []

        ctx[
            "raw_evidence_references"
        ] = raw_references

    finding_references = ctx.get(
        "finding_evidence_references"
    )

    if not isinstance(
        finding_references,
        list,
    ):
        finding_references = []

        ctx[
            "finding_evidence_references"
        ] = finding_references

    correlated_references = ctx.get(
        "correlated_evidence_references"
    )

    if not isinstance(
        correlated_references,
        list,
    ):
        correlated_references = []

        ctx[
            "correlated_evidence_references"
        ] = correlated_references

    all_references: list[dict[str, Any]] = []

    for collection in (
        raw_references,
        finding_references,
        correlated_references,
    ):

        for reference in collection:

            if isinstance(
                reference,
                dict,
            ):
                _append_unique_reference(
                    all_references,
                    reference,
                )

    ctx[
        "evidence_references"
    ] = all_references


def _initialize_evidence_manager(
    ctx: dict[str, Any],
) -> None:
    """
    Initialize the canonical evidence manager for the current assessment run.

    EvidenceStore receives its own ``evidence/`` namespace so it does not
    collide with the existing workflow ``raw/`` execution-output directory.
    """

    outdir = str(
        ctx.get(
            "outdir",
            "",
        )
    ).strip()

    if not outdir:
        raise ValueError(
            "Cannot initialize evidence storage without workflow output directory."
        )

    evidence_root = (
        Path(
            outdir
        )
        / "evidence"
    )

    evidence_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    manager = EvidenceManager(
        root=evidence_root
    )

    ctx[
        "evidence_manager"
    ] = manager

    ctx[
        "evidence_root"
    ] = str(
        evidence_root.resolve()
    )

    ctx.setdefault(
        "evidence_references",
        [],
    )

    ctx.setdefault(
        "raw_evidence_references",
        [],
    )

    ctx.setdefault(
        "finding_evidence_references",
        [],
    )

    ctx.setdefault(
        "correlated_evidence_references",
        [],
    )

    ctx.setdefault(
        "_persisted_finding_evidence_ids",
        set(),
    )

    ctx.setdefault(
        "_persisted_correlated_evidence_ids",
        set(),
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

    WorkflowEngine owns orchestration only.

    ToolExecutor remains responsible for:

    - execution
    - collection
    - finding normalization
    - risk classification
    - deduplication
    - correlation

    EvidenceManager remains responsible for:

    - evidence persistence
    - evidence references
    - evidence provenance

    The workflow exposes the resulting assessment state to reporting and
    downstream consumers through ``ctx``.
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

            "collector_results": [],

            "native_analyzer_results": [],

            "vulnerability_intelligence_results": [],

            "findings": [],

            "correlation_groups": [],

            "correlated_findings": [],

            "analysis_result": {},

            "analysis": {},

            "evidence_manager": None,

            "evidence_root": "",

            "evidence_references": [],

            "raw_evidence_references": [],

            "finding_evidence_references": [],

            "correlated_evidence_references": [],

            "_persisted_finding_evidence_ids": set(),

            "_persisted_correlated_evidence_ids": set(),
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

        self.ctx[
            "profile"
        ] = self.profile_name

        self.ctx[
            "profile_config"
        ] = self.profile

        self.ctx[
            "runtime"
        ] = self.runtime

        list_keys = (
            "execution_results",
            "stage_results",
            "collector_results",
            "native_analyzer_results",
            "vulnerability_intelligence_results",
            "findings",
            "correlation_groups",
            "correlated_findings",
            "evidence_references",
            "raw_evidence_references",
            "finding_evidence_references",
            "correlated_evidence_references",
        )

        for key in list_keys:

            if not isinstance(
                self.ctx.get(
                    key
                ),
                list,
            ):

                self.ctx[
                    key
                ] = []

        for key in (
            "analysis_result",
            "analysis",
        ):

            if not isinstance(
                self.ctx.get(
                    key
                ),
                dict,
            ):

                self.ctx[
                    key
                ] = {}

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

        _initialize_evidence_manager(
            self.ctx
        )

        assessment_context(
            target=str(
                self.ctx.get(
                    "target",
                    "",
                )
            ).strip(),
            profile=self.profile_name,
            authorized=bool(
                self.ctx.get(
                    "authorized",
                    False,
                )
            ),
            tool_count=len(
                self.selected_tools
            ),
        )

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
            owns process execution, collection and finding analysis.
        """

        name = _tool_name(
            tool
        )

        capability = _tool_capability(
            tool
        )

        _prepare_tool_input_data(
            ctx,
            tool,
            self.executor,
        )

        if not name:

            raise ValueError(
                "Selected tool definition has no valid name."
            )

        if not capability:

            raise ValueError(
                f"Tool '{name}' has no canonical capability metadata."
            )

        tool_context = self._create_tool_context(
            tool,
            ctx,
            profile,
        )

        adapter = create_tool_adapter(
            name,
            context=tool_context,
        )

        execution_context = self._build_tool_context(
            ctx,
            tool,
            profile,
        )

        result = self.executor.execute(
            adapter,
            execution_context,
        )

        _sync_executor_state(
            ctx,
            self.executor,
        )

        return result

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
                "[bold cyan]{task.description}"
            ),
            BarColumn(),
            TextColumn(
                "[bold]{task.completed}/{task.total}"
            ),
            TimeElapsedColumn(),
        ) as progress:

            task = progress.add_task(
                (
                    f"  {self.profile_name.upper()} "
                    "│ INITIALIZING"
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

                    progress.update(
                        task,
                        description=(
                            f"  {phase.value.upper()} "
                            f"│ {name} "
                            f"│ {capability or 'unknown'}"
                        ),
                    )

                    workflow_tool_start(
                        phase.value,
                        name,
                        capability,
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

                    _sync_executor_state(
                        self.ctx,
                        self.executor,
                    )

                    _persist_assessment_evidence(
                        self.ctx,
                        result,
                    )

                    result_status = str(
                        getattr(
                            result,
                            "status",
                            "failed",
                        )
                        or "failed"
                    ).strip().lower()

                    if result_status == "skipped":
                        display_status = "SKIPPED"
                    elif result_status == "success":
                        display_status = "SUCCESS"
                    else:
                        display_status = "FAILED"

                    workflow_tool_result(
                        phase.value,
                        name,
                        capability,
                        result_status,
                    )

                    progress.update(
                        task,
                        description=(
                            f"  {phase.value.upper()} "
                            f"│ {name} "
                            f"│ {display_status}"
                        ),
                    )

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

        _sync_executor_state(
            self.ctx,
            self.executor,
        )

        _persist_assessment_evidence(
            self.ctx
        )

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

        _sync_executor_state(
            self.ctx,
            self.executor,
        )

        _persist_assessment_evidence(
            self.ctx
        )

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

    The final terminal presentation is security-first: findings and risk are
    shown before execution telemetry, with direct paths to both report views.
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

    assessment_summary(
        ctx
    )

    return ctx


__all__ = [
    "WorkflowEngine",
    "run_profile",
]
