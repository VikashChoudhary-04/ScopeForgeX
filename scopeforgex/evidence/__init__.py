"""
ScopeForgeX Evidence Package
=============================

Evidence storage and lifecycle management for ScopeForgeX.

The evidence layer provides a controlled boundary between raw tool output,
normalized findings, and reporting.

Architecture
------------

External Tool
    |
    v
Runtime Artifact
    |
    v
Evidence Store
    |
    v
Evidence Manager
    |
    +--> Finding Analysis
    |
    +--> Reporting
    |
    v
Assessment Evidence

Responsibilities
----------------

The evidence package is responsible for:

- Organizing raw assessment evidence.
- Providing stable evidence references.
- Keeping evidence separate from finding metadata.
- Preserving tool output for later analysis.
- Supporting assessment-specific output directories.
- Preventing reporting code from depending directly on tool execution.

The evidence layer does not:

- Execute external tools.
- Construct tool commands.
- Parse tool-specific output.
- Determine finding severity.
- Perform vulnerability detection.

Those responsibilities belong to the runtime, collector, analyzer, and
finding layers respectively.

v1.0.0
"""

from __future__ import annotations


###############################################################################
# Public API
###############################################################################

# Lazy imports keep package initialization lightweight and reduce the
# possibility of circular imports between evidence, runtime, findings, and
# reporting.


__all__ = [
    "EvidenceStore",
    "EvidenceManager",
]


def __getattr__(
    name: str,
):
    """
    Lazily expose evidence components.
    """

    if name == "EvidenceStore":
        from .store import EvidenceStore

        return EvidenceStore

    if name == "EvidenceManager":
        from .manager import EvidenceManager

        return EvidenceManager

    raise AttributeError(
        f"module {__name__!r} has no attribute {name!r}"
    )
