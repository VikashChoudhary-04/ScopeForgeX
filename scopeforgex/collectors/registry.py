"""
ScopeForgeX Collector Registry
==============================

Canonical registry for the ScopeForgeX external-tool collectors.

The collector registry provides the single resolution layer between the
canonical ToolDefinition metadata and the concrete collector implementations.

Architecture
------------

ToolDefinition
    |
    v
Collector Registry
    |
    v
Collector
    |
    v
CollectorResult
    |
    v
CollectorObservation
    |
    v
Finding Analysis Pipeline

Design Principles
-----------------

- Every core external tool has exactly one primary collector.
- Collector resolution is independent from workflow orchestration.
- Collectors never execute external tools.
- Legacy ``reporting.parsers`` modules are not used by the runtime.
- ``testssl.sh`` resolves to the canonical ``testssl`` collector key.
- Registry lookups always return fresh collector instances.
- Unknown tools fail explicitly.
- ToolDefinition metadata remains the source of the canonical tool name.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from typing import Any

from scopeforgex.collectors.amass import AmassCollector
from scopeforgex.collectors.dalfox import DalfoxCollector
from scopeforgex.collectors.dig import DigCollector
from scopeforgex.collectors.ffuf import FFUFCollector
from scopeforgex.collectors.hashcat import HashcatCollector
from scopeforgex.collectors.httpx import HTTPXCollector
from scopeforgex.collectors.hydra import HydraCollector
from scopeforgex.collectors.jsluice import JSLuiceCollector
from scopeforgex.collectors.jwt_tool import JwtToolCollector
from scopeforgex.collectors.katana import KatanaCollector
from scopeforgex.collectors.kiterunner import KiterunnerCollector
from scopeforgex.collectors.nikto import NiktoCollector
from scopeforgex.collectors.nmap import NmapCollector
from scopeforgex.collectors.nuclei import NucleiCollector
from scopeforgex.collectors.sqlmap import SQLMapCollector
from scopeforgex.collectors.sstimap import SSTImapCollector
from scopeforgex.collectors.subhunt import SubhuntCollector
from scopeforgex.collectors.testssl import TestSSLCollector
from scopeforgex.collectors.whatweb import WhatWebCollector


###############################################################################
# Collector Registry
###############################################################################


_COLLECTOR_REGISTRY: dict[str, type[Any]] = {
    "amass": AmassCollector,
    "subhunt": SubhuntCollector,
    "nmap": NmapCollector,
    "dig": DigCollector,
    "httpx": HTTPXCollector,
    "katana": KatanaCollector,
    "ffuf": FFUFCollector,
    "whatweb": WhatWebCollector,
    "kiterunner": KiterunnerCollector,
    "jsluice": JSLuiceCollector,
    "nuclei": NucleiCollector,
    "nikto": NiktoCollector,
    "testssl": TestSSLCollector,
    "sqlmap": SQLMapCollector,
    "dalfox": DalfoxCollector,
    "jwt_tool": JwtToolCollector,
    "sstimap": SSTImapCollector,
    "hydra": HydraCollector,
    "hashcat": HashcatCollector,
}


###############################################################################
# Name Normalization
###############################################################################


def normalize_collector_name(
    name: str,
) -> str:
    """
    Normalize a tool name to its canonical collector key.

    The external executable ``testssl.sh`` maps to the collector implementation
    stored in ``scopeforgex.collectors.testssl``.
    """

    normalized = str(
        name
    ).strip().lower()

    if normalized == "testssl.sh":
        return "testssl"

    return normalized


###############################################################################
# Registry Access
###############################################################################


def get_registered_collectors() -> tuple[str, ...]:
    """
    Return all registered collector keys in deterministic order.
    """

    return tuple(
        sorted(
            _COLLECTOR_REGISTRY
        )
    )


def get_collector_class(
    name: str,
) -> type[Any]:
    """
    Resolve a tool name to its canonical collector class.

    Raises:
        KeyError:
            If no collector is registered.
    """

    normalized = normalize_collector_name(
        name
    )

    try:
        return _COLLECTOR_REGISTRY[
            normalized
        ]
    except KeyError as exc:
        raise KeyError(
            "No ScopeForgeX collector registered for tool: "
            f"{name!r}"
        ) from exc


def create_collector(
    name: str,
) -> Any:
    """
    Create a fresh collector instance for a tool.

    The collector must expose the canonical ``collect()`` interface.
    """

    collector_class = get_collector_class(
        name
    )

    try:
        collector = collector_class()

    except Exception as exc:
        raise TypeError(
            "Could not initialize collector for tool "
            f"{name!r}: {type(exc).__name__}: {exc}"
        ) from exc

    if not callable(
        getattr(
            collector,
            "collect",
            None,
        )
    ):
        raise TypeError(
            f"Collector for tool {name!r} does not expose collect()."
        )

    return collector


def get_collector_for_tool(
    tool: Any,
) -> Any:
    """
    Create the canonical collector associated with a ToolDefinition or
    registry tool object.

    The tool object's canonical ``name`` is authoritative.

    This function intentionally does not resolve or import the legacy
    ``reporting.parsers`` namespace.
    """

    if tool is None:
        raise TypeError(
            "Tool definition cannot be None."
        )

    name = getattr(
        tool,
        "name",
        None,
    )

    if not name:
        raise ValueError(
            "Tool definition must provide a non-empty name."
        )

    return create_collector(
        str(name)
    )


def get_collector_registry() -> dict[str, type[Any]]:
    """
    Return a shallow copy of the collector registry.
    """

    return dict(
        _COLLECTOR_REGISTRY
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "create_collector",
    "get_collector_class",
    "get_collector_for_tool",
    "get_collector_registry",
    "get_registered_collectors",
    "normalize_collector_name",
]
