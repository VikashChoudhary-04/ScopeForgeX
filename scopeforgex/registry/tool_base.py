"""
ScopeForgeX Tool Framework
==========================

Shared abstractions used by the canonical ScopeForgeX 3.0 architecture.

ToolOption
----------
Definition of a configurable tool option.

ToolDefinition
--------------
Static metadata describing a registered assessment tool.

ToolContext
-----------
Typed runtime context supplied to a ToolAdapter.

ToolAdapter
-----------
Canonical adapter contract used by every registered ScopeForgeX tool.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from scopeforgex.models.execution_result import ExecutionResult


###############################################################################
# Tool Metadata
###############################################################################


@dataclass(frozen=True)
class ToolOption:
    """Definition of an option exposed by a ScopeForgeX tool."""

    name: str
    flag: str
    description: str = ""
    option_type: str = "string"
    default: Any = None
    choices: tuple[Any, ...] = ()
    safe: bool = True
    aggressive: bool = False
    repeatable: bool = False


@dataclass(frozen=True)
class ToolDefinition:
    """Static metadata describing an assessment tool."""

    name: str
    capability: str
    phase: str
    purpose: str
    executable: str
    input_type: str
    output_type: str
    finding_types: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    options: tuple[ToolOption, ...] = ()
    safe: bool = True
    aggressive: bool = False


@dataclass
class ToolContext:
    """
    Runtime information supplied to a ToolAdapter.
    """

    target: str
    output_dir: Path
    profile: str = "standard"
    options: Mapping[str, Any] = field(
        default_factory=dict
    )
    input_data: Sequence[str] = field(
        default_factory=tuple
    )


###############################################################################
# Canonical Adapter Contract
###############################################################################


class ToolAdapter(ABC):
    """
    Canonical ScopeForgeX 3.0 tool adapter.

    Every registered tool must implement this contract.

    Adapters own:

    - Tool-specific option validation
    - Tool-specific command construction
    - Tool-specific command arguments

    The execution layer owns process execution.
    """

    definition: ToolDefinition

    # Canonical metadata is intentionally exposed at the adapter-class level
    # as properties so all consumers can use a single runtime interface.
    #
    # These annotations also make the adapter contract explicit for static
    # analysis and runtime inspection.
    input_type: str
    output_type: str

    def __init__(
        self,
        context: ToolContext,
    ) -> None:
        self.context = context

    @property
    def name(self) -> str:
        """Return the canonical tool name."""

        return self.definition.name

    @property
    def capability(self) -> str:
        """Return the canonical capability."""

        return self.definition.capability

    @property
    def phase(self) -> str:
        """Return the canonical workflow phase."""

        return self.definition.phase

    @property
    def purpose(self) -> str:
        """Return the canonical tool purpose."""

        return self.definition.purpose

    @property
    def executable(self) -> str:
        """Return the configured executable name."""

        return self.definition.executable

    @property
    def input_type(self) -> str:
        """Return the canonical input type."""

        return self.definition.input_type

    @property
    def output_type(self) -> str:
        """Return the canonical output type."""

        return self.definition.output_type

    @property
    def finding_types(self) -> tuple[str, ...]:
        """Return canonical finding types."""

        return self.definition.finding_types

    @property
    def options(self) -> tuple[ToolOption, ...]:
        """Return the tool's declared options."""

        return self.definition.options

    def output_path(
        self,
        filename: str,
    ) -> Path:
        """Return a path inside this tool's output directory."""

        path = (
            self.context.output_dir
            / filename
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        return path

    def get_option(
        self,
        name: str,
        default: Any = None,
    ) -> Any:
        """Return a configured option value."""

        return self.context.options.get(
            name,
            default,
        )

    def has_option(
        self,
        name: str,
    ) -> bool:
        """Return whether an option was explicitly configured."""

        return name in self.context.options

    def validate_options(self) -> None:
        """
        Validate configured options against the tool definition.
        """

        supported = {
            option.name
            for option in self.options
        }

        unknown = (
            set(self.context.options)
            - supported
        )

        if unknown:
            names = ", ".join(
                sorted(
                    str(name)
                    for name in unknown
                )
            )

            raise ValueError(
                f"Unsupported option(s) for {self.name}: {names}"
            )

        for option in self.options:
            if option.name not in self.context.options:
                continue

            value = self.context.options[
                option.name
            ]

            if (
                option.choices
                and value not in option.choices
            ):
                choices = ", ".join(
                    map(
                        str,
                        option.choices,
                    )
                )

                raise ValueError(
                    f"Invalid value for {self.name}.{option.name}: "
                    f"{value!r}. Expected one of: {choices}"
                )

    def validate_context(self) -> None:
        """Validate the minimum runtime context required by the adapter."""

        if not self.context.target:
            raise ValueError(
                f"{self.name} requires a target."
            )

        if not self.context.output_dir:
            raise ValueError(
                f"{self.name} requires an output directory."
            )

        self.validate_options()

    def build_command(self) -> list[str]:
        """
        Build the complete command for this adapter.
        """

        self.validate_context()

        command = self.build_base_command()
        command.extend(
            self.build_arguments()
        )

        return command

    def build_base_command(self) -> list[str]:
        """Return the executable portion of the command."""

        return [
            self.executable
        ]

    @abstractmethod
    def build_arguments(self) -> list[str]:
        """Build tool-specific command-line arguments."""

        raise NotImplementedError

    def build_parser_input(
        self,
    ) -> Path | str | Sequence[str]:
        """
        Return the default input passed to the corresponding collector.
        """

        return self.context.output_dir

    def is_safe(self) -> bool:
        """Return whether the adapter is classified as safe by default."""

        return (
            self.definition.safe
            and not self.definition.aggressive
        )

    def requires_confirmation(self) -> bool:
        """Return whether explicit confirmation is required."""

        return (
            self.definition.aggressive
            or not self.definition.safe
        )

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute this adapter through its configured execution layer.

        Tool execution is deliberately centralized in ToolExecutor. A
        ToolAdapter does not spawn subprocesses itself.
        """

        from scopeforgex.runtime.tool_executor import (
            execute_tool,
        )

        return execute_tool(
            self
        )


__all__ = [
    "ToolOption",
    "ToolDefinition",
    "ToolContext",
    "ToolAdapter",
]
