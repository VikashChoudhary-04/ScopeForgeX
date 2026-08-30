"""
ScopeForgeX — Enumeration Stage
================================

Stage 2 of the ScopeForgeX ethical hacking workflow.

Responsibilities
----------------

- Consume outputs produced by Stage 1 reconnaissance.
- Perform configured web and network enumeration.
- Preserve tool execution results and artifacts.
- Feed normalized observations into the universal finding pipeline.
- Keep enumeration separate from vulnerability analysis.
- Continue safely when an individual enumeration tool fails.

Workflow
--------

Stage 1 — Recon
    |
    v
Stage 2 — Enumeration
    |
    +--> Web Enumeration
    +--> Network Enumeration
    +--> HTTP/service discovery
    |
    v
Stage 3 — Vulnerability Identification

Design Principles
-----------------

- Stage 2 orchestrates enumeration; collectors execute individual tools.
- No vulnerability confirmation is performed here.
- No exploitation is performed here.
- Existing Stage 1 artifacts are treated as inputs.
- Tool failures are recorded rather than silently discarded.
- Results remain available to downstream stages.
- The stage remains profile-driven.
- External execution is delegated to the existing execution layer.

v1.3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from scopeforgex.models.execution_result import ExecutionResult


###############################################################################
# Stage Result
###############################################################################


@dataclass(slots=True)
class EnumerationStageResult:
    """
    Aggregate result for Stage 2 enumeration.

    Individual ExecutionResult objects remain intact so downstream processing
    can inspect the output of each enumeration capability independently.
    """

    stage: int = 2

    name: str = "enumeration"

    success: bool = True

    results: list[ExecutionResult] = field(
        default_factory=list,
    )

    artifacts: list[str] = field(
        default_factory=list,
    )

    findings: list[Any] = field(
        default_factory=list,
    )

    warnings: list[str] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def executed_tools(
        self,
    ) -> list[str]:
        """
        Return unique tools that produced execution results.
        """

        tools: list[str] = []

        for result in self.results:

            tool = str(
                getattr(
                    result,
                    "tool",
                    "",
                )
            ).strip()

            if tool and tool not in tools:
                tools.append(
                    tool
                )

        return tools

    @property
    def failed_tools(
        self,
    ) -> list[str]:
        """
        Return tools whose execution failed.
        """

        tools: list[str] = []

        for result in self.results:

            if getattr(
                result,
                "success",
                False,
            ):
                continue

            tool = str(
                getattr(
                    result,
                    "tool",
                    "",
                )
            ).strip()

            if tool and tool not in tools:
                tools.append(
                    tool
                )

        return tools

    def add_result(
        self,
        result: ExecutionResult,
    ) -> None:
        """
        Add an execution result and merge its aggregate data.
        """

        if result is None:
            return

        self.results.append(
            result
        )

        for artifact in getattr(
            result,
            "artifacts",
            [],
        ):
            if artifact not in self.artifacts:
                self.artifacts.append(
                    artifact
                )

        for finding in getattr(
            result,
            "findings",
            [],
        ):
            if finding not in self.findings:
                self.findings.append(
                    finding
                )

        for warning in getattr(
            result,
            "warnings",
            [],
        ):
            if warning not in self.warnings:
                self.warnings.append(
                    warning
                )

        for error in getattr(
            result,
            "errors",
            [],
        ):
            if error not in self.errors:
                self.errors.append(
                    error
                )

        if not result.success:
            self.success = False

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the stage result.
        """

        return {
            "stage": self.stage,
            "name": self.name,
            "success": self.success,
            "executed_tools": self.executed_tools,
            "failed_tools": self.failed_tools,
            "artifacts": list(
                self.artifacts
            ),
            "findings": [
                (
                    finding.as_dict()
                    if hasattr(
                        finding,
                        "as_dict",
                    )
                    else finding
                )
                for finding in self.findings
            ],
            "warnings": list(
                self.warnings
            ),
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
            "results": [
                result.as_dict()
                for result in self.results
            ],
        }


###############################################################################
# Enumeration Stage
###############################################################################


class EnumerationStage:
    """
    Orchestrate Stage 2 enumeration.

    The stage intentionally contains orchestration logic rather than direct
    subprocess/network logic. Concrete execution is delegated to the supplied
    executor.

    The executor is expected to expose an execution method compatible with:

        execute(tool, capability, ...)

    A callable executor is also accepted.
    """

    stage = 2

    name = "enumeration"

    description = (
        "Enumerate discovered web and network assets using configured "
        "ScopeForgeX collectors."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def run(
        self,
        target: str,
        *,
        executor: Any = None,
        profile: Any = None,
        state: Any = None,
        output_dir: str | Path | None = None,
        web: bool = True,
        network: bool = True,
        tools: Iterable[Any] | None = None,
        **kwargs: Any,
    ) -> EnumerationStageResult:
        """
        Execute Stage 2 enumeration.

        Args:
            target:
                Assessment target.

            executor:
                Existing ScopeForgeX execution layer.

            profile:
                Active workflow profile.

            state:
                Existing workflow state object.

            output_dir:
                Stage output directory.

            web:
                Enable web enumeration.

            network:
                Enable network enumeration.

            tools:
                Optional explicit enumeration tool definitions.

            **kwargs:
                Additional execution context passed to compatible executors.

        Returns:
            EnumerationStageResult.
        """

        if not str(
            target or ""
        ).strip():

            return EnumerationStageResult(
                success=False,
                errors=[
                    "Enumeration target is required."
                ],
            )

        result = EnumerationStageResult()

        result.metadata.update(
            {
                "target": str(
                    target
                ).strip(),
                "profile": self._profile_name(
                    profile
                ),
            }
        )

        if output_dir is not None:

            result.metadata[
                "output_dir"
            ] = str(
                output_dir
            )

        selected_tools = self._select_tools(
            tools,
            profile=profile,
            web=web,
            network=network,
        )

        if not selected_tools:

            result.warnings.append(
                "No enumeration tools were selected for Stage 2."
            )

            return result

        for tool in selected_tools:

            execution = self._execute_tool(
                tool,
                target=target,
                executor=executor,
                profile=profile,
                state=state,
                output_dir=output_dir,
                **kwargs,
            )

            result.add_result(
                execution
            )

        result.metadata[
            "tool_count"
        ] = len(
            result.results
        )

        result.metadata[
            "successful_tools"
        ] = sum(
            1
            for execution in result.results
            if execution.success
        )

        result.metadata[
            "failed_tools"
        ] = len(
            result.failed_tools
        )

        return result

    ###########################################################################
    # Tool Selection
    ###########################################################################

    @classmethod
    def _select_tools(
        cls,
        tools: Iterable[Any] | None,
        *,
        profile: Any = None,
        web: bool,
        network: bool,
    ) -> list[Any]:
        """
        Select tools from explicit input or profile configuration.

        Explicit tools take precedence over profile-derived tools.
        """

        if tools is not None:

            selected: list[Any] = []

            for tool in tools:

                if tool is None:
                    continue

                category = cls._tool_category(
                    tool
                )

                if category == "web" and not web:
                    continue

                if category == "network" and not network:
                    continue

                selected.append(
                    tool
                )

            return selected

        configured = cls._profile_tools(
            profile
        )

        selected = []

        for tool in configured:

            category = cls._tool_category(
                tool
            )

            if category == "web" and web:
                selected.append(
                    tool
                )

            elif category == "network" and network:
                selected.append(
                    tool
                )

        return selected

    @staticmethod
    def _profile_tools(
        profile: Any,
    ) -> list[Any]:
        """
        Extract Stage 2 tools from a profile-like object.

        Several common ScopeForgeX configuration representations are accepted
        without coupling the stage to one concrete configuration class.
        """

        if profile is None:
            return []

        if isinstance(
            profile,
            Mapping,
        ):

            for key in (
                "stage2_tools",
                "enumeration_tools",
                "enum_tools",
            ):

                value = profile.get(
                    key
                )

                if value:
                    return list(
                        value
                    )

            stage2 = profile.get(
                "stage2"
            )

            if isinstance(
                stage2,
                Mapping,
            ):

                value = stage2.get(
                    "tools"
                )

                if value:
                    return list(
                        value
                    )

            return []

        for attribute in (
            "stage2_tools",
            "enumeration_tools",
            "enum_tools",
        ):

            value = getattr(
                profile,
                attribute,
                None,
            )

            if value:
                return list(
                    value
                )

        return []

    ###########################################################################
    # Execution
    ###########################################################################

    @classmethod
    def _execute_tool(
        cls,
        tool: Any,
        *,
        target: str,
        executor: Any,
        profile: Any,
        state: Any,
        output_dir: str | Path | None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """
        Execute one enumeration tool through the supplied execution layer.
        """

        tool_name = cls._tool_name(
            tool
        )

        capability = cls._tool_capability(
            tool
        )

        if executor is None:

            return ExecutionResult.skipped(
                tool=tool_name or "unknown",
                capability=capability or "enumeration",
                reason=(
                    "No execution layer was supplied for Stage 2."
                ),
            )

        try:

            if hasattr(
                executor,
                "execute",
            ):

                value = executor.execute(
                    tool,
                    target=target,
                    capability=capability,
                    profile=profile,
                    state=state,
                    output_dir=output_dir,
                    **kwargs,
                )

            elif callable(
                executor
            ):

                value = executor(
                    tool,
                    target=target,
                    capability=capability,
                    profile=profile,
                    state=state,
                    output_dir=output_dir,
                    **kwargs,
                )

            else:

                return ExecutionResult.failure(
                    tool=tool_name or "unknown",
                    capability=capability or "enumeration",
                    error=(
                        "Supplied execution layer does not expose "
                        "an execute method or callable interface."
                    ),
                )

            if isinstance(
                value,
                ExecutionResult,
            ):
                return value

            if isinstance(
                value,
                Mapping,
            ):

                return cls._result_from_mapping(
                    value,
                    tool=tool_name,
                    capability=capability,
                )

            return ExecutionResult.success_result(
                tool=tool_name or "unknown",
                capability=capability or "enumeration",
                metadata={
                    "executor_result": value,
                },
            )

        except Exception as exc:
            return ExecutionResult.failure(
                tool=tool_name or "unknown",
                capability=capability or "enumeration",
                error=str(
                    exc
                ),
            )

    @staticmethod
    def _result_from_mapping(
        data: Mapping[str, Any],
        *,
        tool: str,
        capability: str,
    ) -> ExecutionResult:
        """
        Adapt a mapping returned by a compatible executor.
        """

        result = ExecutionResult(
            tool=str(
                data.get(
                    "tool",
                    tool or "unknown",
                )
            ),
            capability=str(
                data.get(
                    "capability",
                    capability or "enumeration",
                )
            ),
            success=bool(
                data.get(
                    "success",
                    False,
                )
            ),
            stdout=str(
                data.get(
                    "stdout",
                    "",
                )
                or ""
            ),
            stderr=str(
                data.get(
                    "stderr",
                    "",
                )
                or ""
            ),
            artifacts=list(
                data.get(
                    "artifacts",
                    [],
                )
                or []
            ),
            findings=list(
                data.get(
                    "findings",
                    [],
                )
                or []
            ),
            warnings=list(
                data.get(
                    "warnings",
                    [],
                )
                or []
            ),
            errors=list(
                data.get(
                    "errors",
                    [],
                )
                or []
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
                or {}
            ),
        )

        return result

    ###########################################################################
    # Tool Metadata
    ###########################################################################

    @staticmethod
    def _tool_name(
        tool: Any,
    ) -> str:
        """
        Resolve a tool name from a string, mapping or tool object.
        """

        if isinstance(
            tool,
            str,
        ):
            return tool.strip()

        if isinstance(
            tool,
            Mapping,
        ):

            return str(
                tool.get(
                    "tool",
                    tool.get(
                        "name",
                        "",
                    ),
                )
                or ""
            ).strip()

        return str(
            getattr(
                tool,
                "name",
                getattr(
                    tool,
                    "tool",
                    "",
                ),
            )
            or ""
        ).strip()

    @staticmethod
    def _tool_capability(
        tool: Any,
    ) -> str:
        """
        Resolve a tool capability.
        """

        if isinstance(
            tool,
            Mapping,
        ):

            return str(
                tool.get(
                    "capability",
                    "enumeration",
                )
                or "enumeration"
            ).strip()

        return str(
            getattr(
                tool,
                "capability",
                "enumeration",
            )
            or "enumeration"
        ).strip()

    @staticmethod
    def _tool_category(
        tool: Any,
    ) -> str:
        """
        Resolve a tool category.

        Unknown tools are treated as web enumeration only when no explicit
        category is supplied.
        """

        if isinstance(
            tool,
            Mapping,
        ):

            category = tool.get(
                "category",
                tool.get(
                    "type",
                    "",
                ),
            )

        else:

            category = getattr(
                tool,
                "category",
                getattr(
                    tool,
                    "type",
                    "",
                ),
            )

        category = str(
            category or ""
        ).strip().lower()

        if category in {
            "network",
            "network_enum",
            "network-enumeration",
        }:
            return "network"

        if category in {
            "web",
            "web_enum",
            "web-enumeration",
        }:
            return "web"

        return "web"

    ###########################################################################
    # State Integration
    ###########################################################################

    @staticmethod
    def _profile_name(
        profile: Any,
    ) -> str:
        """
        Resolve a human-readable profile name.
        """

        if profile is None:
            return ""

        if isinstance(
            profile,
            Mapping,
        ):

            return str(
                profile.get(
                    "name",
                    profile.get(
                        "profile",
                        "",
                    ),
                )
                or ""
            ).strip()

        return str(
            getattr(
                profile,
                "name",
                getattr(
                    profile,
                    "profile",
                    "",
                ),
            )
            or ""
        ).strip()


###############################################################################
# Module-Level Convenience API
###############################################################################


def run_enumeration(
    target: str,
    **kwargs: Any,
) -> EnumerationStageResult:
    """
    Execute Stage 2 through a new EnumerationStage instance.
    """

    return EnumerationStage().run(
        target,
        **kwargs,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "EnumerationStageResult",
    "EnumerationStage",
    "run_enumeration",
]
