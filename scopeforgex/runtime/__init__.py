"""
ScopeForgeX Runtime
===================

Public package interface for the ScopeForgeX runtime subsystem.

The runtime package intentionally avoids eagerly importing heavyweight
runtime components such as ToolExecutor.

This is important because registry and tool-base modules depend on runtime
enums. Eagerly importing ToolExecutor from this package during package
initialization creates the following circular dependency:

    tool_base
        ↓
    runtime.enums
        ↓
    runtime.__init__
        ↓
    tool_executor
        ↓
    tool_registry
        ↓
    tool_base

Runtime components are therefore exposed through lazy attribute resolution.

v1.1.0
"""

from __future__ import annotations

from typing import Any


###############################################################################
# Package Metadata
###############################################################################

__version__ = "1.1.0"


###############################################################################
# Lazy Public API
###############################################################################


def __getattr__(
    name: str,
) -> Any:
    """
    Lazily resolve public runtime components.

    Lazy imports prevent runtime package initialization from importing
    ToolExecutor before registry/tool-base initialization has completed.
    """

    if name in {
        "AssessmentPhase",
        "ExecutionStatus",
        "Severity",
        "Confidence",
        "get_phase_order",
        "get_phase_order_map",
    }:
        from scopeforgex.runtime import enums

        return getattr(
            enums,
            name,
        )

    if name in {
        "RuntimeState",
        "ExecutionState",
        "utc_now",
    }:
        from scopeforgex.runtime import state

        return getattr(
            state,
            name,
        )

    if name == "ToolExecutor":
        from scopeforgex.runtime import tool_executor

        return tool_executor.ToolExecutor

    return _raise_missing_attribute(name)


def _raise_missing_attribute(
    name: str,
) -> Any:
    """
    Raise the standard module attribute error.

    Kept separate so __getattr__ remains straightforward and readable.
    """

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


###############################################################################
# Public API
###############################################################################

__all__ = [
    "AssessmentPhase",
    "ExecutionStatus",
    "Severity",
    "Confidence",
    "get_phase_order",
    "get_phase_order_map",
    "RuntimeState",
    "ExecutionState",
    "utc_now",
    "ToolExecutor",
]
