"""
ScopeForgeX Tool Execution Layer
================================

Canonical execution layer for ScopeForgeX tool adapters.

Responsibilities:

- Execute new-style ToolAdapter commands.
- Preserve legacy ToolAdapter compatibility during migration.
- Respect adapter-owned custom run() execution contracts.
- Measure execution duration.
- Apply execution context.
- Capture execution status.
- Convert unexpected adapter failures into ExecutionResult failures.
- Invoke canonical collectors after tool execution.
- Invoke configured native analyzers against already-collected evidence.
- Feed collector and native-analyzer observations into the canonical
  finding-analysis pipeline.
- Preserve raw execution output and generated artifacts.
- Maintain executor-wide finding state so cross-tool deduplication and
  correlation operate across the complete assessment.
- Record execution results in RuntimeState.
- Maintain a consistent execution contract.

Architecture
------------

Workflow
    ↓
Tool Registry
    ↓
Tool Adapter
    ↓
Tool Executor
    ↓
Adapter Execution Contract
    |
    +-- custom adapter run()
    |
    +-- generic build_command()
    |
    +-- legacy run(ctx)
    ↓
ExecutionResult
    ↓
Collector
    ↓
CollectorResult / Observations
    ↓
Native Analyzer Engine
    ↓
Native Analyzer Results / Observations
    ↓
Assessment-Wide AnalysisPipeline
    |
    +-- normalization
    +-- confidence
    +-- risk classification
    +-- deduplication
    +-- correlation
    ↓
Final Findings
    ↓
Runtime / Workflow State
    ↓
Evidence / Reporting

Custom adapter run() implementations remain authoritative.

The executor never performs a second subprocess execution merely to collect
or analyze output.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import os

from dataclasses import dataclass
from time import monotonic
from typing import Any, Iterable, Mapping

from scopeforgex.analysis.pipeline import (
    AnalysisPipeline,
)
from scopeforgex.analyzers.engine import (
    NativeAnalyzerEngine,
)
from scopeforgex.collectors.base import (
    CollectorResult,
)
from scopeforgex.collectors.registry import (
    get_collector_for_tool,
)
from scopeforgex.findings.correlator import (
    FindingCorrelator,
)
from scopeforgex.findings.deduplicator import (
    FindingDeduplicator,
)
from scopeforgex.findings.normalizer import (
    FindingNormalizer,
)
from scopeforgex.findings.risk import (
    FindingRiskClassifier,
)
from scopeforgex.intelligence.engine import (
    VulnerabilityIntelligenceEngine,
)
from scopeforgex.models.execution_result import (
    ExecutionResult,
)
from scopeforgex.registry.tool_registry import (
    get_tool_definition,
)


###############################################################################
# Execution Record
###############################################################################


@dataclass(frozen=True, slots=True)
class ToolExecutionRecord:
    """
    Immutable summary of one tool execution.
    """

    tool: str

    capability: str

    status: str

    started_at: float

    finished_at: float

    duration: float

    success: bool

    exit_code: int | None = None

    error: str | None = None

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the execution record.
        """

        return {
            "tool": self.tool,
            "capability": self.capability,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": self.duration,
            "success": self.success,
            "exit_code": self.exit_code,
            "error": self.error,
        }


###############################################################################
# Tool Executor
###############################################################################


class ToolExecutor:
    """
    Canonical ScopeForgeX tool execution coordinator.

    ToolExecutor coordinates execution but does not construct
    tool-specific arguments.

    Adapter execution precedence is:

    1. Custom ToolAdapter run() implementation.
    2. New-style build_command() execution path.
    3. Legacy run(ctx) compatibility path.

    Collection and native analysis occur only after an execution result already
    exists. Neither operation launches the external executable a second time.

    The executor owns one assessment-wide AnalysisPipeline instance and one
    native-analyzer engine for the lifetime of the executor. A WorkflowEngine
    normally uses one ToolExecutor for one assessment.
    """

    def __init__(
        self,
        runtime_state: Any | None = None,
        *,
        default_timeout: int = 600,
    ) -> None:
        """
        Initialize the execution layer.

        Args:
            runtime_state:
                Optional RuntimeState instance used to record execution.

            default_timeout:
                Default command timeout exposed to adapters through ctx.
        """

        if (
            not isinstance(
                default_timeout,
                int,
            )
            or isinstance(
                default_timeout,
                bool,
            )
        ):
            raise TypeError(
                "default_timeout must be an integer."
            )

        if default_timeout <= 0:
            raise ValueError(
                "default_timeout must be greater than zero."
            )

        self.runtime_state = runtime_state

        self.default_timeout = (
            default_timeout
        )

        # One canonical finding-analysis pipeline per assessment.
        normalizer = FindingNormalizer()

        self.analysis_pipeline = AnalysisPipeline(
            normalizer=normalizer,
            risk=FindingRiskClassifier(),
            deduplicator=FindingDeduplicator(
                normalizer=normalizer,
            ),
            correlator=FindingCorrelator(),
        )

        # Native analyzers are evidence-driven and do not execute tools.
        self.native_analyzer_engine = (
            NativeAnalyzerEngine()
        )

        self._observations: list[Any] = []

        self._collector_results: list[Any] = []

        self._native_analyzer_results: list[Any] = []

        self.vulnerability_intelligence_allow_network = self._environment_bool(
            "SCOPEFORGEX_VULNERABILITY_INTELLIGENCE_NETWORK"
        )

        self.vulnerability_intelligence = VulnerabilityIntelligenceEngine(
            allow_network=self.vulnerability_intelligence_allow_network,
        )

        self._vulnerability_intelligence_results: list[Any] = []

        self._analysis_result: Any | None = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _environment_bool(
        name: str,
        default: bool = False,
    ) -> bool:
        """
        Resolve a boolean configuration value from the environment.
        """

        value = os.getenv(
            name,
        )

        if value is None:
            return default

        return value.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    @staticmethod
    def _tool_name(
        adapter: Any,
    ) -> str:
        """
        Resolve the canonical tool name.
        """

        return str(
            getattr(
                adapter,
                "name",
                adapter.__class__.__name__,
            )
        ).strip().lower()

    @staticmethod
    def _capability(
        adapter: Any,
    ) -> str:
        """
        Resolve the canonical capability name.
        """

        capability = getattr(
            adapter,
            "capability",
            None,
        )

        if capability is None:
            definition = getattr(
                adapter,
                "definition",
                None,
            )

            capability = getattr(
                definition,
                "capability",
                None,
            )

        if capability is None:
            return "unknown"

        return str(
            getattr(
                capability,
                "value",
                capability,
            )
        )

    @staticmethod
    def _status(
        result: Any,
    ) -> str:
        """
        Resolve an execution result status.
        """

        value = getattr(
            result,
            "status",
            None,
        )

        if value is None:
            return (
                "success"
                if bool(
                    getattr(
                        result,
                        "success",
                        False,
                    )
                )
                else "failed"
            )

        return str(
            getattr(
                value,
                "value",
                value,
            )
        )

    @staticmethod
    def _exit_code(
        result: Any,
    ) -> int | None:
        """
        Resolve an optional process exit code.
        """

        value = getattr(
            result,
            "exit_code",
            None,
        )

        if value is None:
            value = getattr(
                getattr(
                    result,
                    "metadata",
                    {},
                ),
                "exit_code",
                None,
            )

        if value is None:
            return None

        try:
            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _error(
        result: Any,
    ) -> str | None:
        """
        Resolve an optional execution error.

        ExecutionResult currently stores errors as a collection, but older
        callers may expose a singular error attribute. Both representations
        are supported.
        """

        value = getattr(
            result,
            "error",
            None,
        )

        if value is not None:
            return str(
                value
            )

        errors = getattr(
            result,
            "errors",
            None,
        )

        if isinstance(
            errors,
            Iterable,
        ) and not isinstance(
            errors,
            (str, bytes),
        ):
            for error in errors:
                if error:
                    return str(
                        error
                    )

        return None

    @staticmethod
    def _is_new_adapter(
        adapter: Any,
    ) -> bool:
        """
        Return True when the adapter exposes the new ToolAdapter command
        construction contract.
        """

        return callable(
            getattr(
                adapter,
                "build_command",
                None,
            )
        ) and callable(
            getattr(
                adapter,
                "build_arguments",
                None,
            )
        )

    @staticmethod
    def _has_custom_run(
        adapter: Any,
    ) -> bool:
        """
        Return True when a ToolAdapter provides its own run() implementation.
        """

        try:
            from scopeforgex.registry.tool_base import (
                ToolAdapter,
            )

        except ImportError:
            return False

        if not isinstance(
            adapter,
            ToolAdapter,
        ):
            return False

        adapter_run = getattr(
            type(adapter),
            "run",
            None,
        )

        if not callable(
            adapter_run
        ):
            return False

        base_run = getattr(
            ToolAdapter,
            "run",
            None,
        )

        return (
            base_run is None
            or adapter_run is not base_run
        )

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------

    def _prepare_context(
        self,
        adapter: Any,
        ctx: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Prepare an isolated execution context.

        Mutable assessment collections supplied by the workflow remain
        available through their original object references.
        """

        context = dict(
            ctx or {}
        )

        tool_name = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        context.setdefault(
            "tool",
            tool_name,
        )

        context.setdefault(
            "capability",
            capability,
        )

        context.setdefault(
            "timeout",
            self.default_timeout,
        )

        context.setdefault(
            "tool_timeout",
            context.get(
                "timeout",
                self.default_timeout,
            ),
        )

        context.setdefault(
            "analysis_pipeline",
            self.analysis_pipeline,
        )

        return context

    # ------------------------------------------------------------------
    # Runtime State
    # ------------------------------------------------------------------

    def _record_result(
        self,
        result: Any,
    ) -> None:
        """
        Record an ExecutionResult in RuntimeState when available.
        """

        if self.runtime_state is None:
            return

        add_tool_result = getattr(
            self.runtime_state,
            "add_tool_result",
            None,
        )

        if callable(
            add_tool_result
        ):
            add_tool_result(
                result
            )

    # ------------------------------------------------------------------
    # Result Metadata
    # ------------------------------------------------------------------

    @staticmethod
    def _add_execution_metadata(
        result: ExecutionResult,
        *,
        tool: str,
        capability: str,
        started_at: float,
        finished_at: float,
        duration: float,
    ) -> None:
        """
        Add standardized execution metadata.
        """

        metadata = getattr(
            result,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):
            return

        metadata.update(
            {
                "execution": {
                    "tool": tool,
                    "capability": capability,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "duration": duration,
                    "status": ToolExecutor._status(
                        result
                    ),
                    "success": bool(
                        getattr(
                            result,
                            "success",
                            False,
                        )
                    ),
                    "exit_code": ToolExecutor._exit_code(
                        result
                    ),
                    "error": ToolExecutor._error(
                        result
                    ),
                }
            }
        )

    # ------------------------------------------------------------------
    # Collector Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collector_observations(
        collected: Any,
    ) -> list[Any]:
        """
        Extract observations from supported collector return shapes.
        """

        if collected is None:
            return []

        if isinstance(
            collected,
            CollectorResult,
        ):
            return list(
                collected.observations
            )

        if isinstance(
            collected,
            Mapping,
        ):
            for key in (
                "observations",
                "findings",
                "results",
                "data",
            ):
                value = collected.get(
                    key
                )

                if value is None:
                    continue

                if isinstance(
                    value,
                    (str, bytes),
                ):
                    return [
                        value
                    ]

                if isinstance(
                    value,
                    Iterable,
                ):
                    return list(
                        value
                    )

                return [
                    value
                ]

            return []

        if isinstance(
            collected,
            (str, bytes),
        ):
            return [
                collected
            ]

        if isinstance(
            collected,
            Iterable,
        ):
            return list(
                collected
            )

        return [
            collected
        ]

    @staticmethod
    def _collector_metadata(
        collected: Any,
    ) -> dict[str, Any]:
        """
        Extract serializable collector metadata where available.
        """

        if collected is None:
            return {}

        if isinstance(
            collected,
            CollectorResult,
        ):
            return {
                "tool": collected.tool,
                "success": collected.success,
                "observation_count": (
                    collected.observation_count
                ),
                "warnings": list(
                    collected.warnings
                ),
                "errors": list(
                    collected.errors
                ),
                "source_files": list(
                    collected.source_files
                ),
                "metadata": dict(
                    collected.metadata
                ),
            }

        as_dict = getattr(
            collected,
            "as_dict",
            None,
        )

        if callable(
            as_dict
        ):
            try:
                value = as_dict()
            except Exception:
                return {}

            if isinstance(
                value,
                Mapping,
            ):
                return dict(
                    value
                )

        if isinstance(
            collected,
            Mapping,
        ):
            return dict(
                collected
            )

        return {
            "success": True,
            "observation_count": len(
                ToolExecutor._collector_observations(
                    collected
                )
            ),
            "result_type": (
                "legacy_collection"
            ),
        }

    @staticmethod
    def _legacy_collector_output(
        result: ExecutionResult,
    ) -> str:
        """
        Combine captured process streams for legacy collectors.
        """

        stdout = str(
            getattr(
                result,
                "stdout",
                "",
            )
            or ""
        )

        stderr = str(
            getattr(
                result,
                "stderr",
                "",
            )
            or ""
        )

        if stdout and stderr:
            return (
                stdout
                + "\n"
                + stderr
            )

        return stdout or stderr

    @staticmethod
    def _invoke_collector(
        collector: Any,
        result: ExecutionResult,
        context: Mapping[str, Any],
    ) -> Any:
        """
        Invoke a collector without executing the external tool.
        """

        collect = getattr(
            collector,
            "collect",
            None,
        )

        if not callable(
            collect
        ):
            return None

        try:
            from scopeforgex.collectors.base import (
                CollectorBase,
            )

            if isinstance(
                collector,
                CollectorBase,
            ):
                return collect(
                    result,
                    context,
                )

        except Exception:
            pass

        output = ToolExecutor._legacy_collector_output(
            result
        )

        target = str(
            context.get(
                "target",
                "",
            )
            or ""
        )

        metadata = {
            "run_id": context.get(
                "run_id"
            ),
            "profile": context.get(
                "profile"
            ),
            "tool": context.get(
                "tool"
            ),
        }

        try:
            return collect(
                output,
                target=target,
                metadata=metadata,
            )

        except TypeError as first_error:
            try:
                options = dict(
                    context.get(
                        "tool_options",
                        {},
                    )
                    or {}
                )

                options.setdefault(
                    "result",
                    result,
                )

                options.setdefault(
                    "output",
                    output,
                )

                options.setdefault(
                    "target",
                    target,
                )

                return collect(
                    target=target,
                    options=options,
                )

            except TypeError:
                raise first_error

    # ------------------------------------------------------------------
    # Collector Metadata
    # ------------------------------------------------------------------

    def _record_collector_result(
        self,
        result: ExecutionResult,
        collected: Any,
        *,
        tool: str,
    ) -> None:
        """
        Attach canonical collector information to the ExecutionResult.
        """

        metadata = getattr(
            result,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):
            return

        collector_data = (
            ToolExecutor._collector_metadata(
                collected
            )
        )

        collector_name = None

        if isinstance(
            collected,
            CollectorResult,
        ):
            collector_name = collected.tool

        elif isinstance(
            collected,
            Mapping,
        ):
            collector_name = collected.get(
                "tool"
            )

        else:
            collector_name = getattr(
                collected,
                "tool",
                None,
            )

        metadata[
            "collector"
        ] = {
            "tool": tool,
            "collector": str(
                collector_name
                or tool
            ),
        }

        # Always expose collector_result when a collection boundary completed.
        metadata[
            "collector_result"
        ] = collector_data

    # ------------------------------------------------------------------
    # Native Analyzer Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _native_analyzer_key(
        name: Any,
    ) -> str:
        """
        Normalize native-analyzer profile/configuration names.

        Historical profile names are mapped to canonical analyzer names.
        """

        normalized = str(
            name
            or ""
        ).strip().lower()

        aliases = {
            "security_headers": (
                "http_security_headers"
            ),
            "headers": (
                "http_security_headers"
            ),
            "http_headers": (
                "http_security_headers"
            ),
            "cookies": "cookies",
            "cookie": "cookies",
            "cors": "cors",
            "http_methods": "http_methods",
            "methods": "http_methods",
            "sensitive_files": (
                "sensitive_information"
            ),
            "sensitive_information": (
                "sensitive_information"
            ),
            "api": "api",
        }

        return aliases.get(
            normalized,
            normalized,
        )

    @classmethod
    def _native_analyzers_enabled(
        cls,
        context: Mapping[str, Any],
    ) -> set[str] | None:
        """
        Resolve enabled native analyzers from workflow profile configuration.

        Returns:
            A canonical enabled-analyzer set.

            ``None`` means no explicit native-analyzer configuration is
            available and the executor should use all engine analyzers.
        """

        profile_config = context.get(
            "profile_config"
        )

        if not isinstance(
            profile_config,
            Mapping,
        ):
            return None

        configured = profile_config.get(
            "native_analyzers"
        )

        if not isinstance(
            configured,
            Mapping,
        ):
            return None

        enabled: set[str] = set()

        for name, config in configured.items():

            if isinstance(
                config,
                Mapping,
            ):
                is_enabled = bool(
                    config.get(
                        "enabled",
                        False,
                    )
                )

            else:
                is_enabled = bool(
                    config
                )

            if not is_enabled:
                continue

            enabled.add(
                cls._native_analyzer_key(
                    name
                )
            )

        return enabled

    @classmethod
    def _native_analyzer_engine(
        cls,
        engine: NativeAnalyzerEngine,
        context: Mapping[str, Any],
    ) -> NativeAnalyzerEngine:
        """
        Return a native analyzer engine filtered by profile configuration.
        """

        enabled = cls._native_analyzers_enabled(
            context
        )

        if enabled is None:
            return engine

        selected = [
            analyzer
            for analyzer in engine.analyzers
            if cls._native_analyzer_key(
                getattr(
                    analyzer,
                    "name",
                    "",
                )
            ) in enabled
        ]

        return NativeAnalyzerEngine(
            analyzers=selected,
        )

    @staticmethod
    def _serialize_native_analyzer_result(
        result: Any,
    ) -> dict[str, Any]:
        """
        Serialize one native AnalyzerResult safely.
        """

        if result is None:
            return {}

        as_dict = getattr(
            result,
            "as_dict",
            None,
        )

        if callable(
            as_dict
        ):
            try:
                value = as_dict()
            except Exception:
                value = None

            if isinstance(
                value,
                Mapping,
            ):
                return dict(
                    value
                )

        serialized: dict[str, Any] = {
            "analyzer": str(
                getattr(
                    result,
                    "analyzer",
                    "",
                )
            ),
            "success": bool(
                getattr(
                    result,
                    "success",
                    False,
                )
            ),
            "findings": [],
            "errors": list(
                getattr(
                    result,
                    "errors",
                    [],
                )
                or []
            ),
            "metadata": dict(
                getattr(
                    result,
                    "metadata",
                    {},
                )
                or {}
            ),
        }

        findings = getattr(
            result,
            "findings",
            [],
        )

        for finding in findings or []:

            finding_as_dict = getattr(
                finding,
                "as_dict",
                None,
            )

            if callable(
                finding_as_dict
            ):
                try:
                    serialized[
                        "findings"
                    ].append(
                        finding_as_dict()
                    )
                    continue
                except Exception:
                    pass

            if isinstance(
                finding,
                Mapping,
            ):
                serialized[
                    "findings"
                ].append(
                    dict(
                        finding
                    )
                )

            else:
                serialized[
                    "findings"
                ].append(
                    finding
                )

        serialized[
            "finding_count"
        ] = len(
            serialized[
                "findings"
            ]
        )

        return serialized

    @staticmethod
    def _serialize_observation(
        observation: Any,
    ) -> Any:
        """
        Serialize one observation without discarding structured data.
        """

        as_dict = getattr(
            observation,
            "as_dict",
            None,
        )

        if callable(
            as_dict
        ):
            try:
                return as_dict()
            except Exception:
                pass

        if isinstance(
            observation,
            Mapping,
        ):
            return dict(
                observation
            )

        return observation

    def _native_analyzer_evidence(
        self,
        result: ExecutionResult,
        collected: Any,
        observations: list[Any],
        context: Mapping[str, Any],
    ) -> dict[str, Any]:
        """
        Build the evidence mapping consumed by native analyzers.

        Evidence is derived exclusively from data already available from the
        execution result, collector result, and workflow context.
        """

        evidence: dict[str, Any] = {}

        evidence[
            "tool"
        ] = context.get(
            "tool"
        )

        evidence[
            "capability"
        ] = context.get(
            "capability"
        )

        evidence[
            "target"
        ] = context.get(
            "target"
        )

        evidence[
            "profile"
        ] = context.get(
            "profile"
        )

        evidence[
            "run_id"
        ] = context.get(
            "run_id"
        )

        evidence[
            "stdout"
        ] = result.stdout

        evidence[
            "stderr"
        ] = result.stderr

        evidence[
            "artifacts"
        ] = list(
            result.artifacts
        )

        serialized_observations: list[Any] = []

        for observation in observations:
            serialized_observations.append(
                self._serialize_observation(
                    observation
                )
            )

        evidence[
            "collector_observations"
        ] = serialized_observations

        if isinstance(
            collected,
            CollectorResult,
        ):
            collector_data = (
                collected.as_dict()
            )

            evidence[
                "collector_result"
            ] = collector_data

            collector_metadata = (
                collector_data.get(
                    "metadata",
                    {},
                )
                if isinstance(
                    collector_data,
                    Mapping,
                )
                else {}
            )

            if isinstance(
                collector_metadata,
                Mapping,
            ):
                for key, value in collector_metadata.items():
                    evidence.setdefault(
                        key,
                        value
                    )

        else:

            collector_data = (
                ToolExecutor._collector_metadata(
                    collected
                )
            )

            if collector_data:
                evidence[
                    "collector_result"
                ] = collector_data

        # Preserve explicit HTTP/security evidence supplied by workflow
        # context. Explicit context values take precedence over defaults.
        for key in (
            "headers",
            "response_headers",
            "http_headers",
            "request_headers",
            "set_cookie",
            "cookies",
            "methods",
            "allowed_methods",
            "http_methods",
            "request_origin",
            "url",
            "host",
            "port",
            "http_response",
            "http_responses",
        ):

            if key in context:
                evidence.setdefault(
                    key,
                    context.get(
                        key
                    ),
                )

        # If the collector exposed a structured URL/host/port, preserve those
        # values for native analyzers without inventing HTTP response data.
        for key in (
            "url",
            "host",
            "port",
        ):
            if key not in evidence:
                value = context.get(
                    key
                )

                if value is not None:
                    evidence[
                        key
                    ] = value

        return evidence

    def _run_native_analyzers(
        self,
        result: ExecutionResult,
        collected: Any,
        observations: list[Any],
        context: Mapping[str, Any],
    ) -> list[Any]:
        """
        Execute configured native analyzers against already-collected evidence.

        Native analyzer state is attached to every completed execution where
        the native-analysis boundary is reached, even if zero native findings
        are generated.

        Native analyzers never execute the source tool.
        """

        metadata = getattr(
            result,
            "metadata",
            None,
        )

        if not isinstance(
            metadata,
            dict,
        ):
            return []

        engine = self._native_analyzer_engine(
            self.native_analyzer_engine,
            context,
        )

        if not engine.analyzers:
            metadata[
                "native_analyzers"
            ] = {
                "results": [],
                "finding_count": 0,
                "enabled": [],
                "analyzer_count": 0,
            }

            return []

        evidence = self._native_analyzer_evidence(
            result,
            collected,
            observations,
            context,
        )

        try:
            analyzer_results = (
                engine.analyze_with_results(
                    evidence
                )
            )

        except Exception as exc:

            metadata[
                "native_analyzers"
            ] = {
                "results": [],
                "finding_count": 0,
                "enabled": [],
                "analyzer_count": 0,
                "error": (
                    f"{type(exc).__name__}: {exc}"
                ),
            }

            result.add_warning(
                (
                    "Native analyzer execution failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

            return []

        self._native_analyzer_results.extend(
            analyzer_results
        )

        serialized_results = [
            self._serialize_native_analyzer_result(
                item
            )
            for item in analyzer_results
        ]

        native_observations: list[Any] = []

        for analyzer_result in analyzer_results:
            native_observations.extend(
                getattr(
                    analyzer_result,
                    "findings",
                    [],
                )
                or []
            )

            analyzer_errors = getattr(
                analyzer_result,
                "errors",
                [],
            )

            for error in analyzer_errors or []:

                shared_errors = context.get(
                    "errors"
                )

                if isinstance(
                    shared_errors,
                    list,
                ):
                    shared_errors.append(
                        (
                            "Native analyzer "
                            f"{getattr(analyzer_result, 'analyzer', '')}: "
                            f"{error}"
                        )
                    )

        metadata[
            "native_analyzers"
        ] = {
            "results": serialized_results,
            "finding_count": len(
                native_observations
            ),
            "enabled": [
                str(
                    getattr(
                        item,
                        "analyzer",
                        "",
                    )
                )
                for item in analyzer_results
            ],
            "analyzer_count": len(
                analyzer_results
            ),
        }

        return native_observations

    # ------------------------------------------------------------------
    # Vulnerability Intelligence
    # ------------------------------------------------------------------

    def _run_vulnerability_intelligence(
        self,
        observations: list[Any],
        context: Mapping[str, Any],
    ) -> list[Any]:
        """Enrich software/version observations through vulnerability intelligence."""

        if not observations:
            return []

        allow_network = context.get(
            "vulnerability_intelligence_allow_network"
        )

        if allow_network is not None:
            self.vulnerability_intelligence.allow_network = bool(
                allow_network
            )

        try:
            results = self.vulnerability_intelligence.analyze(
                observations
            )
        except Exception as exc:
            errors = context.get("errors")
            if isinstance(errors, list):
                errors.append(
                    "Vulnerability intelligence failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            return []

        results = list(results or [])
        self._vulnerability_intelligence_results.extend(results)
        return results

    # ------------------------------------------------------------------
    # Collector + Analysis
    # ------------------------------------------------------------------

    def _analyze_observations(
        self,
        observations: list[Any],
        *,
        context: Mapping[str, Any],
    ) -> Any | None:
        """
        Add observations to the assessment-wide analysis set and reprocess
        the complete set.

        Reprocessing the complete observation set ensures findings from
        different tools and analyzers enter the same deduplication and
        correlation scope.
        """

        if not observations:
            return self._analysis_result

        self._observations.extend(
            observations
        )

        try:

            analysis_result = (
                self.analysis_pipeline.process(
                    self._observations
                )
            )

        except Exception as exc:

            self._analysis_result = None

            shared_errors = context.get(
                "errors"
            )

            if isinstance(
                shared_errors,
                list,
            ):
                shared_errors.append(
                    (
                        "Finding analysis failed: "
                        f"{type(exc).__name__}: {exc}"
                    )
                )

            return None

        self._analysis_result = (
            analysis_result
        )

        return analysis_result

    @staticmethod
    def _serialize_analysis_result(
        analysis_result: Any,
    ) -> dict[str, Any]:
        """
        Serialize an AnalysisResult safely.
        """

        if analysis_result is None:
            return {}

        as_dict = getattr(
            analysis_result,
            "as_dict",
            None,
        )

        if callable(
            as_dict
        ):
            try:
                value = as_dict()
            except Exception:
                value = None

            if isinstance(
                value,
                Mapping,
            ):
                return dict(
                    value
                )

        data: dict[str, Any] = {}

        for attribute in (
            "input_count",
            "finding_count",
            "duplicate_count",
            "error_count",
            "errors",
            "metadata",
        ):

            if not hasattr(
                analysis_result,
                attribute,
            ):
                continue

            value = getattr(
                analysis_result,
                attribute,
            )

            if attribute == "errors":
                value = (
                    list(
                        value
                    )
                    if isinstance(
                        value,
                        list,
                    )
                    else value
                )

            elif (
                attribute == "metadata"
                and isinstance(
                    value,
                    Mapping,
                )
            ):
                value = dict(
                    value
                )

            data[
                attribute
            ] = value

        return data

    @staticmethod
    def _serialize_findings(
        analysis_result: Any,
    ) -> list[Any]:
        """
        Serialize final findings from an analysis result.
        """

        if analysis_result is None:
            return []

        findings = getattr(
            analysis_result,
            "findings",
            [],
        )

        serialized: list[Any] = []

        for finding in findings:

            as_dict = getattr(
                finding,
                "as_dict",
                None,
            )

            if callable(
                as_dict
            ):
                try:
                    serialized.append(
                        as_dict()
                    )
                    continue
                except Exception:
                    pass

            if isinstance(
                finding,
                Mapping,
            ):
                serialized.append(
                    dict(
                        finding
                    )
                )

            else:
                serialized.append(
                    finding
                )

        return serialized

    @staticmethod
    def _serialize_correlation_groups(
        analysis_result: Any,
    ) -> list[Any]:
        """
        Serialize correlation groups from an analysis result.
        """

        if analysis_result is None:
            return []

        groups = getattr(
            analysis_result,
            "correlation_groups",
            [],
        )

        serialized: list[Any] = []

        for group in groups:

            as_dict = getattr(
                group,
                "as_dict",
                None,
            )

            if callable(
                as_dict
            ):
                try:
                    serialized.append(
                        as_dict()
                    )
                    continue
                except Exception:
                    pass

            if isinstance(
                group,
                Mapping,
            ):
                serialized.append(
                    dict(
                        group
                    )
                )

            else:
                serialized.append(
                    group
                )

        return serialized

    def _attach_analysis_result(
        self,
        result: ExecutionResult,
        analysis_result: Any | None,
        context: Mapping[str, Any],
    ) -> None:
        """
        Attach final analysis state to the ExecutionResult and shared
        workflow collections.
        """

        if analysis_result is None:
            return

        findings = self._serialize_findings(
            analysis_result
        )

        groups = self._serialize_correlation_groups(
            analysis_result
        )

        analysis_data = (
            self._serialize_analysis_result(
                analysis_result
            )
        )

        analysis_data[
            "findings"
        ] = findings

        analysis_data[
            "correlation_groups"
        ] = groups

        metadata = getattr(
            result,
            "metadata",
            None,
        )

        if isinstance(
            metadata,
            dict,
        ):
            metadata[
                "analysis"
            ] = analysis_data

            metadata[
                "findings"
            ] = findings

            metadata[
                "correlation_groups"
            ] = groups

        existing_result_findings = getattr(
            result,
            "findings",
            None,
        )

        if isinstance(
            existing_result_findings,
            list,
        ):
            existing_result_findings.clear()

            existing_result_findings.extend(
                getattr(
                    analysis_result,
                    "findings",
                    [],
                )
            )

        shared_findings = context.get(
            "findings"
        )

        if isinstance(
            shared_findings,
            list,
        ):
            shared_findings.clear()

            shared_findings.extend(
                getattr(
                    analysis_result,
                    "findings",
                    [],
                )
            )

        shared_groups = context.get(
            "correlation_groups"
        )

        if isinstance(
            shared_groups,
            list,
        ):
            shared_groups.clear()

            shared_groups.extend(
                getattr(
                    analysis_result,
                    "correlation_groups",
                    [],
                )
            )

        context_analysis = context.get(
            "analysis_result"
        )

        if isinstance(
            context_analysis,
            dict,
        ):
            context_analysis.clear()

            context_analysis.update(
                analysis_data
            )

        context_analysis_alias = context.get(
            "analysis"
        )

        if isinstance(
            context_analysis_alias,
            dict,
        ):
            context_analysis_alias.clear()

            context_analysis_alias.update(
                analysis_data
            )

    def _collect_result(
        self,
        adapter: Any,
        result: ExecutionResult,
        context: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """
        Collect and analyze an already-completed tool execution.

        Processing order:

        ExecutionResult
            ↓
        Collector
            ↓
        Collector observations
            ↓
        Native analyzers
            ↓
        Native observations
            ↓
        ONE assessment-wide AnalysisPipeline
            ↓
        Final Findings / Correlation Groups

        This method never launches the external tool.
        """

        execution_context = dict(
            context or {}
        )

        tool = self._tool_name(
            adapter
        )

        try:

            definition = (
                get_tool_definition(
                    tool
                )
            )

            collector = (
                get_collector_for_tool(
                    definition
                )
            )

        except Exception as exc:

            result.add_warning(
                (
                    "Tool result collector resolution failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

            return result

        try:

            collected = (
                self._invoke_collector(
                    collector,
                    result,
                    execution_context,
                )
            )

        except Exception as exc:

            result.add_warning(
                (
                    "Tool result collection failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            )

            # Even when the collector fails, native analyzer state must remain
            # explicit so downstream consumers can distinguish "not run" from
            # "ran and produced no findings".
            self._run_native_analyzers(
                result,
                None,
                [],
                execution_context,
            )

            return result

        # Every execution reaching the collector boundary gets exactly one
        # collector result entry.
        self._collector_results.append(
            collected
        )

        self._record_collector_result(
            result,
            collected,
            tool=tool,
        )

        observations = (
            self._collector_observations(
                collected
            )
        )

        if isinstance(
            collected,
            CollectorResult,
        ):

            for warning in collected.warnings:

                result.add_warning(
                    str(
                        warning
                    )
                )

            for error in collected.errors:

                result.add_warning(
                    (
                        f"Collector error: {error}"
                    )
                )

        # Native analyzers run for EVERY collected execution.
        native_observations = (
            self._run_native_analyzers(
                result,
                collected,
                observations,
                execution_context,
            )
        )

        # Collector and native analyzer observations are enriched by the
        # vulnerability-intelligence layer before entering the single
        # assessment-wide analysis pipeline.
        intelligence_observations = (
            self._run_vulnerability_intelligence(
                [
                    *self._observations,
                    *observations,
                    *native_observations,
                ],
                execution_context,
            )
        )

        all_observations = [
            *observations,
            *native_observations,
            *intelligence_observations,
        ]

        if not all_observations:
            return result

        analysis_result = (
            self._analyze_observations(
                all_observations,
                context=execution_context,
            )
        )

        self._attach_analysis_result(
            result,
            analysis_result,
            execution_context,
        )

        return result

    # ------------------------------------------------------------------
    # Canonical Command Execution
    # ------------------------------------------------------------------

    def _execute_command(
        self,
        adapter: Any,
        context: dict[str, Any],
    ) -> ExecutionResult:
        """
        Build and execute a new-style adapter command.
        """

        tool = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        try:

            command = adapter.build_command()

        except Exception as exc:

            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool command construction failed: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        if not isinstance(
            command,
            (list, tuple),
        ):

            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool adapter build_command() must return "
                    "a list or tuple of command arguments."
                ),
            )

        command = [
            str(argument)
            for argument in command
        ]

        if not command:

            return self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Tool adapter produced an empty command."
                ),
            )

        return self._run_process(
            tool=tool,
            capability=capability,
            command=command,
            context=context,
        )

    # ------------------------------------------------------------------
    # Process Execution
    # ------------------------------------------------------------------

    @staticmethod
    def _run_process(
        *,
        tool: str,
        capability: str,
        command: list[str],
        context: Mapping[str, Any],
    ) -> ExecutionResult:
        """
        Execute a fully constructed command through the existing runner.
        """

        from scopeforgex.runner import run_command

        timeout = context.get(
            "tool_timeout",
            context.get(
                "timeout",
                600,
            ),
        )

        outfile = context.get(
            "outfile"
        )

        cwd = context.get(
            "cwd"
        )

        env = context.get(
            "env"
        )

        command_text = _command_to_string(
            command
        )

        return run_command(
            tool=tool,
            capability=capability,
            cmd=command_text,
            outfile=(
                str(outfile)
                if outfile is not None
                else None
            ),
            timeout=int(
                timeout
            ),
            cwd=(
                str(cwd)
                if cwd is not None
                else None
            ),
            env=(
                dict(env)
                if isinstance(
                    env,
                    Mapping,
                )
                else None
            ),
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        adapter: Any,
        ctx: Mapping[str, Any] | None = None,
    ) -> ExecutionResult:
        """
        Execute one ScopeForgeX tool adapter.

        Execution precedence:

        1. Custom ToolAdapter run().
        2. New-style build_command().
        3. Legacy run(ctx).

        All completed ExecutionResult instances pass through the same
        collector/native-analysis boundary.
        """

        tool = self._tool_name(
            adapter
        )

        capability = self._capability(
            adapter
        )

        context = self._prepare_context(
            adapter,
            ctx,
        )

        started_at = monotonic()

        try:

            if self._is_new_adapter(
                adapter
            ):

                result = self._execute_command(
                    adapter,
                    context,
                )

            elif self._has_custom_run(
                adapter
            ):

                run = getattr(
                    adapter,
                    "run",
                )

                result = run()

            else:

                run = getattr(
                    adapter,
                    "run",
                    None,
                )

                if not callable(
                    run
                ):
                    raise TypeError(
                        "Tool adapter must expose either "
                        "build_command() or run(ctx)."
                    )

                result = run(
                    context
                )

            if isinstance(
                result,
                ExecutionResult,
            ):
                result = self._collect_result(
                    adapter,
                    result,
                    context,
                )

        except KeyboardInterrupt:
            raise

        except Exception as exc:

            result = self._failure_result(
                tool=tool,
                capability=capability,
                error=(
                    "Unhandled tool adapter exception: "
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        finished_at = monotonic()

        duration = (
            finished_at
            - started_at
        )

        if isinstance(
            result,
            ExecutionResult,
        ):

            result.duration = (
                duration
                if result.duration <= 0
                else result.duration
            )

            self._add_execution_metadata(
                result,
                tool=tool,
                capability=capability,
                started_at=started_at,
                finished_at=finished_at,
                duration=duration,
            )

        self._record_result(
            result
        )

        return result

    # ------------------------------------------------------------------
    # Batch Execution
    # ------------------------------------------------------------------

    def execute_many(
        self,
        adapters: list[Any] | tuple[Any, ...],
        ctx: Mapping[str, Any] | None = None,
    ) -> list[ExecutionResult]:
        """
        Execute multiple tool adapters sequentially.

        Execution order is preserved.

        The same executor instance is used for the complete batch, meaning
        collector and native-analyzer observations enter the same analysis
        scope.
        """

        results: list[ExecutionResult] = []

        for adapter in adapters:

            result = self.execute(
                adapter,
                ctx,
            )

            results.append(
                result
            )

        return results

    # ------------------------------------------------------------------
    # Analysis State
    # ------------------------------------------------------------------

    @property
    def observations(
        self,
    ) -> list[Any]:
        """
        Return observations collected during this assessment.
        """

        return list(
            self._observations
        )

    @property
    def collector_results(
        self,
    ) -> list[Any]:
        """
        Return collector results accumulated by this executor.
        """

        return list(
            self._collector_results
        )

    @property
    def native_analyzer_results(
        self,
    ) -> list[Any]:
        """
        Return native analyzer results accumulated by this executor.
        """

        return list(
            self._native_analyzer_results
        )

    @property
    def vulnerability_intelligence_results(
        self,
    ) -> list[Any]:
        """Return vulnerability-intelligence observations accumulated by this executor."""

        return list(
            self._vulnerability_intelligence_results
        )

    @property
    def analysis_result(
        self,
    ) -> Any | None:
        """
        Return the most recent assessment-wide AnalysisResult.
        """

        return self._analysis_result

    @property
    def findings(
        self,
    ) -> list[Any]:
        """
        Return the latest assessment-wide final findings.
        """

        if self._analysis_result is None:
            return []

        return list(
            getattr(
                self._analysis_result,
                "findings",
                [],
            )
        )

    @property
    def correlation_groups(
        self,
    ) -> list[Any]:
        """
        Return the latest assessment-wide correlation groups.
        """

        if self._analysis_result is None:
            return []

        return list(
            getattr(
                self._analysis_result,
                "correlation_groups",
                [],
            )
        )

    # ------------------------------------------------------------------
    # Failure Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _failure_result(
        *,
        tool: str,
        capability: str,
        error: str,
    ) -> ExecutionResult:
        """
        Construct a canonical ExecutionResult failure.
        """

        return ExecutionResult.failure(
            tool=tool,
            capability=capability,
            error=error,
        )


###############################################################################
# Command Formatting
###############################################################################


def _command_to_string(
    command: list[str],
) -> str:
    """
    Convert a structured command into a safely quoted shell command.
    """

    import shlex

    return shlex.join(
        command
    )


###############################################################################
# Convenience Function
###############################################################################


def execute_tool(
    adapter: Any,
    ctx: Mapping[str, Any] | None = None,
    *,
    runtime_state: Any | None = None,
    timeout: int = 600,
) -> ExecutionResult:
    """
    Execute one tool through the canonical ToolExecutor.
    """

    executor = ToolExecutor(
        runtime_state=runtime_state,
        default_timeout=timeout,
    )

    return executor.execute(
        adapter,
        ctx,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "ToolExecutionRecord",
    "ToolExecutor",
    "execute_tool",
]
