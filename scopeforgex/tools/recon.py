"""
ScopeForgeX Reconnaissance Tools
================================

Final reconnaissance tool collection.

Approved tools
--------------
- Amass
- Subhunt
- Nmap
- dig

Design principle
----------------
Each integrated tool must provide a distinct assessment capability and
produce meaningful structured assessment information.

Reconnaissance capabilities
----------------------------
Amass
    Broad attack-surface and infrastructure discovery.

Subhunt
    Active wordlist-based subdomain discovery.

Nmap
    Port, service, version and NSE-based network assessment.

dig
    Deterministic DNS record inspection.
"""

from __future__ import annotations

from scopeforgex.tools.recon_amass import AmassTool
from scopeforgex.tools.recon_subhunt import SubhuntTool
from scopeforgex.tools.recon_nmap import NmapTool
from scopeforgex.tools.recon_dig import DigTool


# ============================================================================
# Canonical Reconnaissance Collection
# ============================================================================

ALL_RECON_TOOLS = [
    AmassTool(),
    SubhuntTool(),
    NmapTool(),
    DigTool(),
]


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "ALL_RECON_TOOLS",
    "AmassTool",
    "SubhuntTool",
    "NmapTool",
    "DigTool",
]
