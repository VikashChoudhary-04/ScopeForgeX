"""
ScopeForgeX Registry
====================

Public registry API for ScopeForgeX 3.0.0.

The registry package exposes the canonical adapter primitives directly while
loading the registry implementation lazily. Lazy loading prevents circular
imports when individual tool modules import ``scopeforgex.registry.tool_base``.
"""

from __future__ import annotations

from typing import Any

from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolContext,
    ToolDefinition as AdapterToolDefinition,
    ToolOption,
)


def __getattr__(
    name: str,
) -> Any:
    """
    Lazily expose registry implementation APIs.

    ``scopeforgex.registry.tool_base`` is imported by individual tool modules.
    Importing ``tool_registry`` eagerly from this package would initialize the
    registry while those tool modules are still being imported, creating a
    circular import.

    Registry implementation symbols are therefore resolved only when they
    are explicitly requested.
    """

    if name in {
        "ToolDefinition",
        "register_tool",
        "build_registry",
        "get_registered_tools",
        "get_tool_definition",
        "create_tool_adapter",
        "get_tool_metadata",
        "get_all_tool_metadata",
        "get_tools_by_phase",
        "get_tool_definitions_by_phase",
    }:
        from scopeforgex.registry import tool_registry

        return getattr(
            tool_registry,
            name,
        )

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )


__all__ = [
    "ToolAdapter",
    "ToolContext",
    "ToolOption",
    "AdapterToolDefinition",
    "ToolDefinition",
    "register_tool",
    "build_registry",
    "get_registered_tools",
    "get_tool_definition",
    "create_tool_adapter",
    "get_tool_metadata",
    "get_all_tool_metadata",
    "get_tools_by_phase",
    "get_tool_definitions_by_phase",
]
