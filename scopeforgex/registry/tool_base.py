"""
ScopeForgeX Tool Framework
==========================

Defines the common contract shared by every executable ScopeForgeX tool.

Design Principle
----------------
Every integrated tool must expose:

- A defined assessment phase
- A defined purpose
- A defined input type
- A defined output type
- Structured finding types
- Tool-specific options
- A command-building boundary
- A parsing/collection boundary
- Standard execution through ExecutionResult

Architecture
------------
Tool adapters own:

    - tool metadata
    - option validation
    - command construction
    - output collection

The execution layer owns:

    - external command execution
    - timeout handling
    - stdout/stderr handling
    - process status
    - ExecutionResult creation

The workflow engine must never construct tool-specific commands directly.

The registry provides canonical workflow metadata.

v1.1.0
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.runtime.enums import AssessmentPhase


class ToolBase(ABC):
    """
    Abstract base class for every executable ScopeForgeX tool.

    Tool implementations should define metadata at the class level and
    implement only behavior specific to that tool.

    The workflow engine interacts with tools through this contract rather
    than knowing how individual tools work.
    """

    # ========================================================================
    # Identity
    # ========================================================================

    name: str = "tool"

    display_name: str = "tool"

    description: str = ""

    purpose: str = ""

    # ========================================================================
    # Workflow Classification
    # ========================================================================

    phase: AssessmentPhase | None = None

    # ========================================================================
    # Capability
    # ========================================================================

    capability: str = ""

    # ========================================================================
    # Input / Output Contract
    # ========================================================================

    input_type: str = "target"

    output_type: str = "raw"

    # Finding types this tool can produce.
    finding_types: tuple[str, ...] = ()

    # ========================================================================
    # Execution Policy
    # ========================================================================

    risk: str = "low"

    enabled_by_default: bool = True

    requires_confirmation: bool = False

    # ========================================================================
    # Tool Configuration
    # ========================================================================

    supported_options: tuple[str, ...] = ()

    default_options: Mapping[str, Any] = {}

    # ========================================================================
    # Execution
    # ========================================================================

    @abstractmethod
    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute the tool.

        The tool implementation is responsible for:

        - Reading the supplied execution context
        - Validating tool-specific prerequisites
        - Building the appropriate command
        - Delegating external execution to the execution layer
        - Preserving relevant artifacts
        - Returning an ExecutionResult

        Tool implementations must not directly own subprocess execution.

        Returns:
            ExecutionResult
        """

        raise NotImplementedError

    # ========================================================================
    # Command Construction
    # ========================================================================

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the command for this tool.

        External-command adapters should override this method.

        Command construction belongs to the adapter because only the adapter
        knows the syntax and semantics of the underlying security tool.

        The workflow engine must never construct tool-specific commands.
        """

        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement build_command()."
        )

    # ========================================================================
    # Output Collection
    # ========================================================================

    def collect(
        self,
        result: ExecutionResult,
    ) -> Any:
        """
        Collect and normalize tool output.

        This is the boundary between execution and the finding pipeline.

        Tools producing structured findings should override this method.

        By default, the original ExecutionResult is returned unchanged.
        """

        return result

    # ========================================================================
    # Metadata
    # ========================================================================

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return standardized public tool metadata.

        This representation is intentionally serialization-friendly so the
        registry, CLI, dashboard and reporting layers can consume consistent
        metadata.
        """

        phase = self.phase

        if isinstance(
            phase,
            AssessmentPhase,
        ):
            phase_value = phase.value

        elif phase is None:
            phase_value = ""

        else:
            phase_value = str(
                phase
            )

        return {
            "name": self.name,
            "display_name": (
                self.display_name
                or self.name
            ),
            "description": self.description,
            "purpose": self.purpose,
            "phase": phase_value,
            "capability": self.capability,
            "input_type": self.input_type,
            "output_type": self.output_type,
            "finding_types": list(
                self.finding_types
            ),
            "risk": self.risk,
            "enabled_by_default": (
                self.enabled_by_default
            ),
            "requires_confirmation": (
                self.requires_confirmation
            ),
            "supported_options": list(
                self.supported_options
            ),
            "default_options": dict(
                self.default_options
            ),
        }

    # ========================================================================
    # Option Handling
    # ========================================================================

    def validate_options(
        self,
        options: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Validate and normalize tool options.

        Unknown options are rejected rather than silently ignored.

        Tool-specific validation can be added by overriding this method.

        Args:
            options:
                User-supplied tool options.

        Returns:
            Normalized option dictionary.

        Raises:
            ValueError:
                If an unsupported option is supplied.
        """

        if options is None:
            options = {}

        unknown = (
            set(options)
            - set(self.supported_options)
        )

        if unknown:
            names = ", ".join(
                sorted(
                    str(name)
                    for name in unknown
                )
            )

            raise ValueError(
                f"Unsupported options for {self.name}: {names}"
            )

        normalized = dict(
            self.default_options
        )

        normalized.update(
            options
        )

        return normalized
