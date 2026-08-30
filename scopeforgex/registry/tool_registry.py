"""
ScopeForgeX Tool Registry
=========================

Central registry for the canonical ScopeForgeX 19-tool set.

The registry stores exactly one ToolDefinition for each registered tool.

Every registered factory must be a ToolAdapter class.

Architecture
------------

Tool Registry
    |
    v
ToolDefinition
    |
    v
ToolAdapter class
    |
    v
ToolContext
    |
    v
ToolExecutor

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolContext,
    ToolOption,
)


###############################################################################
# Registry Entry
###############################################################################


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """
    Canonical definition of a ScopeForgeX assessment tool.
    """

    name: str
    factory: type[ToolAdapter]
    capability: str
    phase: str
    purpose: str
    input_type: str
    output_type: str
    finding_types: tuple[str, ...]
    parser: str
    supported_options: tuple[str, ...]
    default_options: Mapping[str, Any]
    safe_options: Mapping[str, Any]
    aggressive_options: Mapping[str, Any]
    dependencies: tuple[str, ...]

    def create(
        self,
        context: ToolContext,
    ) -> ToolAdapter:
        """
        Create a fresh canonical ToolAdapter instance.
        """

        return self.factory(
            context
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """Return canonical registry metadata."""

        return {
            "name": self.name,
            "capability": self.capability,
            "phase": self.phase,
            "purpose": self.purpose,
            "input_type": self.input_type,
            "output_type": self.output_type,
            "finding_types": list(
                self.finding_types
            ),
            "parser": self.parser,
            "supported_options": list(
                self.supported_options
            ),
            "default_options": dict(
                self.default_options
            ),
            "safe_options": dict(
                self.safe_options
            ),
            "aggressive_options": dict(
                self.aggressive_options
            ),
            "dependencies": list(
                self.dependencies
            ),
        }


###############################################################################
# Registry State
###############################################################################


_TOOL_REGISTRY: dict[str, ToolDefinition] = {}


###############################################################################
# Registration
###############################################################################


def register_tool(
    adapter_factory: type[ToolAdapter],
    *,
    capability: str | None = None,
    phase: str | None = None,
    purpose: str | None = None,
    input_type: str | None = None,
    output_type: str | None = None,
    finding_types: tuple[str, ...] | None = None,
    parser: str | None = None,
    supported_options: tuple[str, ...] | None = None,
    default_options: Mapping[str, Any] | None = None,
    safe_options: Mapping[str, Any] | None = None,
    aggressive_options: Mapping[str, Any] | None = None,
    dependencies: tuple[str, ...] | None = None,
) -> None:
    """
    Register one canonical ToolAdapter class.
    """

    if not isinstance(
        adapter_factory,
        type,
    ):
        raise TypeError(
            "Registered tool factory must be a ToolAdapter class."
        )

    if not issubclass(
        adapter_factory,
        ToolAdapter,
    ):
        raise TypeError(
            "Registered tool factory must inherit from ToolAdapter: "
            f"{adapter_factory!r}"
        )

    adapter_definition = getattr(
        adapter_factory,
        "definition",
        None,
    )

    if not isinstance(
        adapter_definition,
        ToolDefinitionBaseAdapter,
    ):
        raise TypeError(
            "ToolAdapter definition must be a "
            "scopeforgex.registry.tool_base.ToolDefinition instance: "
            f"{adapter_factory.__name__}"
        )

    adapter_name = str(
        adapter_definition.name
    ).strip()

    if not adapter_name:
        raise ValueError(
            "Tool name cannot be empty."
        )

    name = adapter_name.lower()

    if name in _TOOL_REGISTRY:
        raise ValueError(
            f"ScopeForgeX tool already registered: {name}"
        )

    resolved_capability = (
        capability
        if capability is not None
        else adapter_definition.capability
    )

    resolved_phase = (
        phase
        if phase is not None
        else adapter_definition.phase
    )

    resolved_purpose = (
        purpose
        if purpose is not None
        else adapter_definition.purpose
    )

    resolved_input_type = (
        input_type
        if input_type is not None
        else adapter_definition.input_type
    )

    resolved_output_type = (
        output_type
        if output_type is not None
        else adapter_definition.output_type
    )

    resolved_finding_types = (
        finding_types
        if finding_types is not None
        else tuple(
            adapter_definition.finding_types
        )
    )

    resolved_parser = (
        parser
        if parser is not None
        else ""
    )

    resolved_supported_options = (
        supported_options
        if supported_options is not None
        else tuple(
            option.name
            for option in adapter_definition.options
        )
    )

    resolved_default_options = (
        default_options
        if default_options is not None
        else {
            option.name: option.default
            for option in adapter_definition.options
            if option.default is not None
        }
    )

    resolved_safe_options = (
        safe_options
        if safe_options is not None
        else {
            option.name: option.default
            for option in adapter_definition.options
            if (
                option.safe
                and option.default is not None
            )
        }
    )

    resolved_aggressive_options = (
        aggressive_options
        if aggressive_options is not None
        else {
            option.name: option.default
            for option in adapter_definition.options
            if (
                option.aggressive
                and option.default is not None
            )
        }
    )

    resolved_dependencies = (
        dependencies
        if dependencies is not None
        else tuple(
            adapter_definition.dependencies
        )
    )

    if not resolved_capability:
        raise ValueError(
            f"Tool capability is required: {name}"
        )

    if not resolved_phase:
        raise ValueError(
            f"Tool phase is required: {name}"
        )

    if not resolved_purpose:
        raise ValueError(
            f"Tool purpose is required: {name}"
        )

    if not resolved_input_type:
        raise ValueError(
            f"Tool input type is required: {name}"
        )

    if not resolved_output_type:
        raise ValueError(
            f"Tool output type is required: {name}"
        )

    if not resolved_finding_types:
        raise ValueError(
            f"Tool finding types are required: {name}"
        )

    if not resolved_parser:
        raise ValueError(
            f"Tool parser/collector is required: {name}"
        )

    _TOOL_REGISTRY[name] = ToolDefinition(
        name=name,
        factory=adapter_factory,
        capability=str(
            resolved_capability
        ),
        phase=str(
            resolved_phase
        ),
        purpose=str(
            resolved_purpose
        ),
        input_type=str(
            resolved_input_type
        ),
        output_type=str(
            resolved_output_type
        ),
        finding_types=tuple(
            resolved_finding_types
        ),
        parser=str(
            resolved_parser
        ),
        supported_options=tuple(
            resolved_supported_options
        ),
        default_options=dict(
            resolved_default_options
        ),
        safe_options=dict(
            resolved_safe_options
        ),
        aggressive_options=dict(
            resolved_aggressive_options
        ),
        dependencies=tuple(
            resolved_dependencies
        ),
    )


###############################################################################
# Registry Definition Type Alias
###############################################################################


# Avoid shadowing the public registry ToolDefinition above while still
# allowing us to validate the metadata class imported from tool_base.py.
from scopeforgex.registry.tool_base import (
    ToolDefinition as ToolDefinitionBaseAdapter,
)


###############################################################################
# Lookup
###############################################################################


def get_registered_tools() -> tuple[str, ...]:
    """Return registered tool names in deterministic registration order."""

    return tuple(
        _TOOL_REGISTRY.keys()
    )


def get_tool_definition(
    name: str,
) -> ToolDefinition:
    """Return the canonical definition for a registered tool."""

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
    context: ToolContext | None = None,
) -> ToolAdapter:
    """
    Create a fresh canonical adapter.

    A ToolContext is mandatory because every registered tool is a native
    ToolAdapter.
    """

    if context is None:
        raise ValueError(
            f"ToolContext is required to create ToolAdapter: {name}"
        )

    return get_tool_definition(
        name
    ).create(
        context
    )


def get_tool_metadata(
    name: str,
) -> dict[str, Any]:
    """Return canonical metadata for a registered tool."""

    return get_tool_definition(
        name
    ).as_dict()


def get_all_tool_metadata() -> list[dict[str, Any]]:
    """Return metadata for every registered tool."""

    return [
        definition.as_dict()
        for definition in _TOOL_REGISTRY.values()
    ]


def get_tools_by_phase(
    phase: str,
) -> tuple[str, ...]:
    """Return registered tool names belonging to a workflow phase."""

    normalized = str(
        phase
    ).strip().lower()

    return tuple(
        definition.name
        for definition in _TOOL_REGISTRY.values()
        if definition.phase.lower()
        == normalized
    )


def get_tool_definitions_by_phase(
    phase: str,
) -> tuple[ToolDefinition, ...]:
    """Return complete definitions belonging to a workflow phase."""

    normalized = str(
        phase
    ).strip().lower()

    return tuple(
        definition
        for definition in _TOOL_REGISTRY.values()
        if definition.phase.lower()
        == normalized
    )


###############################################################################
# Built-in Tool Registration
###############################################################################


def build_registry() -> dict[str, ToolDefinition]:
    """
    Build and return the canonical ScopeForgeX 19-tool registry.

    Registry construction is idempotent.
    """

    if _TOOL_REGISTRY:
        return _TOOL_REGISTRY

    # ========================================================================
    # Stage 1 — Reconnaissance
    # ========================================================================

    from scopeforgex.tools.stage1_recon_network import (
        AmassTool,
        DigTool,
        NmapTool,
    )

    from scopeforgex.tools.stage1_recon_web import (
        SubhuntTool,
    )

    # ========================================================================
    # Stage 2 — Enumeration
    # ========================================================================

    from scopeforgex.tools.stage2_enum_web import (
        FfufTool,
        HttpxTool,
        JSLuiceTool,
        KatanaTool,
        KiterunnerTool,
        WhatWebTool,
    )

    # ========================================================================
    # Stage 3 — Vulnerability Assessment
    # ========================================================================

    from scopeforgex.tools.stage3_vuln import (
        NiktoTool,
        NucleiTool,
    )

    # ========================================================================
    # Stage 4 — Vulnerability Validation
    # ========================================================================

    from scopeforgex.tools.stage4_exploit import (
        DalfoxTool,
        SQLMapTool,
        SSTImapTool,
    )

    # ========================================================================
    # Stage 5 — Credential Assessment
    # ========================================================================

    from scopeforgex.tools.stage5_credential import (
        HashcatTool,
        HydraTool,
    )

    # ========================================================================
    # TLS Security Assessment
    # ========================================================================

    from scopeforgex.tools.stage3_vuln import (
        TestSSLTool,
    )

    # ========================================================================
    # JWT Security Validation
    # ========================================================================

    from scopeforgex.tools.stage4_exploit import (
        JWTTool,
    )

    # ========================================================================
    # Stage 1 — Reconnaissance
    # ========================================================================

    register_tool(
        AmassTool,
        parser="Amass Collector",
        supported_options=(
            "passive",
            "active",
            "brute",
            "timeout",
        ),
        default_options={
            "passive": True,
        },
        safe_options={
            "passive": True,
            "active": False,
            "brute": False,
        },
        aggressive_options={
            "passive": True,
            "active": True,
            "brute": True,
        },
    )

    register_tool(
        SubhuntTool,
        parser="Subhunt Collector",
        supported_options=(
            "wordlist",
            "threads",
            "timeout",
        ),
        default_options={},
        safe_options={
            "threads": 10,
        },
        aggressive_options={
            "threads": 50,
        },
    )

    register_tool(
        NmapTool,
        parser="Nmap Collector",
    )

    register_tool(
        DigTool,
        parser="dig Collector",
    )

    # ========================================================================
    # Stage 2 — Enumeration
    # ========================================================================

    register_tool(
        HttpxTool,
        parser="HTTPX Collector",
    )

    register_tool(
        KatanaTool,
        parser="Katana Collector",
    )

    register_tool(
        FfufTool,
        parser="ffuf Collector",
    )

    register_tool(
        WhatWebTool,
        parser="WhatWeb Collector",
    )

    register_tool(
        KiterunnerTool,
        parser="Kiterunner Collector",
    )

    register_tool(
        JSLuiceTool,
        parser="JSLuice Collector",
    )

    # ========================================================================
    # Stage 3 — Vulnerability Assessment
    # ========================================================================

    register_tool(
        NucleiTool,
        parser="Nuclei Collector",
    )

    register_tool(
        NiktoTool,
        parser="Nikto Collector",
    )

    register_tool(
        TestSSLTool,
        parser="testssl.sh Collector",
    )

    # ========================================================================
    # Stage 4 — Vulnerability Validation
    # ========================================================================

    register_tool(
        SQLMapTool,
        parser="SQLMap Collector",
    )

    register_tool(
        DalfoxTool,
        parser="Dalfox Collector",
    )

    register_tool(
        JWTTool,
        parser="JWT Tool Collector",
    )

    register_tool(
        SSTImapTool,
        parser="SSTImap Collector",
    )

    # ========================================================================
    # Stage 5 — Credential Assessment
    # ========================================================================

    register_tool(
        HydraTool,
        parser="Hydra Collector",
    )

    register_tool(
        HashcatTool,
        parser="Hashcat Collector",
    )

    return _TOOL_REGISTRY


###############################################################################
# Module Initialization
###############################################################################


build_registry()


###############################################################################
# Public API
###############################################################################


__all__ = [
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
