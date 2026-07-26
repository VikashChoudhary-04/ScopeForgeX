"""
ScopeForgeX Tool Groups
=======================

Human-readable names for workflow stages.

Used by the registry, dashboard, reporting, and any UI
components that need to display stage names.

v0.4.0
"""

from __future__ import annotations

# ----------------------------------------------------------------------
# Workflow stage names
# ----------------------------------------------------------------------

TOOL_GROUPS: dict[int, str] = {
    1: "Recon",
    2: "Enumeration",
    3: "Vulnerability Identification",
    4: "Exploitation Prep",
    5: "Post/Creds Prep",
    6: "Reporting",
}
