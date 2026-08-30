"""
ScopeForgeX Registry
====================

Public registry API for ScopeForgeX 3.0.0.
"""

from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolContext,
    ToolDefinition as AdapterToolDefinition,
    ToolOption,
)

from scopeforgex.registry.tool_registry import (
    ToolDefinition,
    build_registry,
    create_tool_adapter,
    get_all_tool_metadata,
    get_registered_tools,
    get_tool_definition,
    get_tool_definitions_by_phase,
    get_tool_metadata,
    get_tools_by_phase,
    register_tool,
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
