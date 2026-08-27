"""
ScopeForgeX Tool Registry
=========================

Canonical registry for all ScopeForgeX assessment capabilities.

The registry is responsible for:

- registering tool adapters
- exposing canonical tool metadata
- creating tool adapter instances
- preserving deterministic registration order
- preventing duplicate tool registrations

The workflow engine must not construct tool-specific commands or import
individual tool implementations directly.

Architecture
------------
Tool Registry
    ↓
Tool Adapter
    ↓
ToolBase
    ↓
Execution Layer

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scopeforgex.registry.tool_base import ToolBase


###############################################################################
# Registry Entry
###############################################################################


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """
    Canonical metadata and factory for a ScopeForgeX tool.
    """

    name: str
    factory: Callable[[], ToolBase]

    def create(self) -> ToolBase:
        """
        Create a fresh adapter instance.
        """

        return self.factory()

    def as_dict(self) -> dict:
        """
        Return canonical tool metadata.
        """

        adapter = self.create()

        return adapter.as_dict()


###############################################################################
# Internal Registry
###############################################################################


_TOOL_REGISTRY: dict[str, ToolDefinition] = {}


###############################################################################
# Registration
###############################################################################


def register_tool(
    adapter_factory: Callable[[], ToolBase],
) -> None:
    """
    Register a ScopeForgeX tool adapter factory.

    Args:
        adapter_factory:
            Callable returning a ToolBase instance.

    Raises:
        TypeError:
            If the factory does not return a ToolBase-compatible object.

        ValueError:
            If the tool name is invalid or already registered.
    """

    adapter = adapter_factory()

    if not isinstance(
        adapter,
        ToolBase,
    ):
        raise TypeError(
            "Tool factory must return a ToolBase instance."
        )

    name = str(
        adapter.name
    ).strip().lower()

    if not name:
        raise ValueError(
            "Tool name cannot be empty."
        )

    if name in _TOOL_REGISTRY:
        raise ValueError(
            f"ScopeForgeX tool already registered: {name}"
        )

    _TOOL_REGISTRY[name] = ToolDefinition(
        name=name,
        factory=adapter_factory,
    )


###############################################################################
# Lookup
###############################################################################


def get_registered_tools() -> tuple[str, ...]:
    """
    Return registered tool names in deterministic order.
    """

    return tuple(
        _TOOL_REGISTRY.keys()
    )


def get_tool_definition(
    name: str,
) -> ToolDefinition:
    """
    Return the canonical definition for a registered tool.
    """

    normalized = str(
        name
    ).strip().lower()

    try:
        return _TOOL_REGISTRY[
            normalized
        ]

    except KeyError as exc:
        raise KeyError(
            f"Unknown ScopeForgeX tool: {name}"
        ) from exc


def create_tool_adapter(
    name: str,
) -> ToolBase:
    """
    Create a fresh adapter for a registered tool.
    """

    return get_tool_definition(
        name
    ).create()


def get_tool_metadata(
    name: str,
) -> dict:
    """
    Return canonical metadata for a registered tool.
    """

    return get_tool_definition(
        name
    ).as_dict()


def get_all_tool_metadata() -> list[dict]:
    """
    Return metadata for every registered tool in registry order.
    """

    return [
        definition.as_dict()
        for definition in _TOOL_REGISTRY.values()
    ]


###############################################################################
# Built-in Tool Registration
###############################################################################


def _register_builtin_tools() -> None:
    """
    Register the complete ScopeForgeX core tool set.

    Tool imports are intentionally performed inside this function.

    This keeps registration explicit while avoiding the circular import
    between the registry package and the runtime execution layer.
    """

    from scopeforgex.tools.stage1_recon_network import (
        AmassTool,
        DigTool,
        NmapTool,
    )

    from scopeforgex.tools.stage1_recon_web import (
        HttpxTool,
        SubhuntTool,
    )

    from scopeforgex.tools.stage2_enum_network import (
        TestSSLTool,
    )

    from scopeforgex.tools.stage2_enum_web import (
        FfufTool,
        JSLuiceTool,
        KatanaTool,
        KiterunnerTool,
        WhatWebTool,
    )

    from scopeforgex.tools.stage3_vuln import (
        NucleiTool,
        NiktoTool,
    )

    from scopeforgex.tools.stage4_exploit import (
        DalfoxTool,
        JWTTool,
        SQLMapTool,
        SSTImapTool,
    )

    from scopeforgex.tools.stage5_post import (
        HashcatTool,
        HydraTool,
    )

    builtins = (
        AmassTool,
        SubhuntTool,
        NmapTool,
        DigTool,
        HttpxTool,
        KatanaTool,
        FfufTool,
        WhatWebTool,
        KiterunnerTool,
        JSLuiceTool,
        NucleiTool,
        NiktoTool,
        TestSSLTool,
        SQLMapTool,
        DalfoxTool,
        JWTTool,
        SSTImapTool,
        HydraTool,
        HashcatTool,
    )

    for factory in builtins:
        register_tool(
            factory
        )


###############################################################################
# Initialize Registry
###############################################################################


_register_builtin_tools()


###############################################################################
# Public API
###############################################################################


# Public compatibility alias.
TOOL_REGISTRY = _TOOL_REGISTRY

# Public canonical definitions.
TOOL_DEFINITIONS = _TOOL_REGISTRY


__all__ = [
    "ToolDefinition",
    "TOOL_REGISTRY",
    "TOOL_DEFINITIONS",
    "register_tool",
    "get_registered_tools",
    "get_tool_definition",
    "create_tool_adapter",
    "get_tool_metadata",
    "get_all_tool_metadata",
]
