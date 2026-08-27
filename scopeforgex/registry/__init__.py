"""
ScopeForgeX Registry
====================

Public registry API for ScopeForgeX tool adapters and tool definitions.

The registry package exposes the canonical tool abstraction without requiring
callers to know the internal module layout.

v1.1.0
"""

from __future__ import annotations


###############################################################################
# Base Tool Abstraction
###############################################################################

from scopeforgex.registry.tool_base import ToolBase


###############################################################################
# Tool Registry
###############################################################################

from scopeforgex.registry.tool_registry import (
    TOOL_DEFINITIONS,
    TOOL_REGISTRY,
    ToolDefinition,
    build_registry,
    create_tool_adapter,
    get_registered_tools,
    get_tool_definition,
    get_tools_by_phase,
)


###############################################################################
# Public API
###############################################################################

__all__ = [
    "ToolBase",
    "ToolDefinition",
    "TOOL_DEFINITIONS",
    "TOOL_REGISTRY",
    "build_registry",
    "create_tool_adapter",
    "get_registered_tools",
    "get_tool_definition",
    "get_tools_by_phase",
]
