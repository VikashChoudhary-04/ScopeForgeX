"""
ScopeForgeX Runtime Artifacts
=============================

Defines immutable models representing artifacts generated during workflow
execution.

Artifacts are the authoritative description of files and other outputs
produced by executors. The runtime records artifact metadata as soon as it is
created, allowing reporters to consume structured data instead of scanning the
filesystem.

Design Principles
-----------------
- Immutable dataclasses.
- Strong typing.
- Standard-library only.
- JSON serialization friendly.
- Filesystem agnostic.
- Thread-safe.

This module intentionally contains no filesystem operations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from .enums import ArtifactType


def utc_now() -> datetime:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc)


# ============================================================================
# Artifact Model
# ============================================================================


@dataclass(frozen=True, slots=True)
class Artifact:
    """
    Represents a single runtime artifact produced during execution.
    """

    name: str

    path: Path

    artifact_type: ArtifactType

    producer: str

    stage: str

    created_at: datetime = field(default_factory=utc_now)

    artifact_id: UUID = field(default_factory=uuid4)

    size: int | None = None

    entries: int | None = None

    checksum: str | None = None

    mime_type: str | None = None

    description: str | None = None

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def filename(self) -> str:
        """Return the filename component."""
        return self.path.name

    @property
    def extension(self) -> str:
        """Return the lowercase file extension."""
        return self.path.suffix.lower()

    @property
    def exists(self) -> bool:
        """
        Indicates whether the artifact currently exists.

        This is informational only and is never used to determine runtime
        execution state.
        """
        return self.path.exists()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "artifact_id": str(self.artifact_id),
            "name": self.name,
            "path": str(self.path),
            "artifact_type": self.artifact_type.value,
            "producer": self.producer,
            "stage": self.stage,
            "created_at": self.created_at.isoformat(),
            "size": self.size,
            "entries": self.entries,
            "checksum": self.checksum,
            "mime_type": self.mime_type,
            "description": self.description,
            "metadata": self.metadata,
        }


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "Artifact",
    "utc_now",
]
