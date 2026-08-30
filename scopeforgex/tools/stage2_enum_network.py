"""
ScopeForgeX
Deprecated Stage 2 Network Enumeration Compatibility Module
=============================================================

The final ScopeForgeX architecture uses Nmap as the primary network
discovery and enumeration tool.

The previous integrations for:

    - enum4linux-ng
    - snmpwalk
    - testssl.sh

are not implemented in this compatibility module.

Nmap owns the primary network discovery capability, including:

    - Port discovery
    - Service detection
    - Version detection
    - NSE security checks
    - Network configuration observations

This module is retained only for compatibility with legacy imports.

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

# Kept only so older code that references the module can continue to import it.
#
# New code must use the canonical ToolRegistry and the appropriate primary
# tool adapter instead.
ALL_STAGE2_NET_ENUM_TOOLS: list[object] = []


__all__ = [
    "ALL_STAGE2_NET_ENUM_TOOLS",
]
