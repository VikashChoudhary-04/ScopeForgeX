"""
ScopeForgeX
Deprecated Stage 2 Network Enumeration Compatibility Module
=============================================================

The final ScopeForgeX architecture uses Nmap as the primary network
discovery and enumeration tool.

The previous integrations for:

    - enum4linux-ng
    - snmpwalk

were removed from the core toolchain because they do not provide enough
distinct capability to justify maintaining separate automatic integrations.

Nmap now owns the primary network discovery capability, including:

    - Port discovery
    - Service detection
    - Version detection
    - NSE security checks
    - Network configuration observations

This module is retained temporarily for compatibility with legacy imports.

It intentionally contains no executable tool integrations.

Final architecture principle:

    One capability
        ↓
    One primary tool
        ↓
    Structured finding
        ↓
    Evidence
        ↓
    Correlation
        ↓
    Report
"""

from __future__ import annotations


###############################################################################
# Deprecated Compatibility
###############################################################################

# Kept only so older imports do not fail.
#
# New code must use the canonical ToolRegistry and NmapTool instead.
ALL_STAGE2_NET_ENUM_TOOLS: list[object] = []


__all__ = [
    "ALL_STAGE2_NET_ENUM_TOOLS",
]
