"""
ScopeForgeX Runtime Artifacts
=============================

Defines the canonical artifact representation used throughout ScopeForgeX.

Artifacts represent files and other persistent outputs produced during an
assessment. They provide a consistent interface for execution, workflow and
reporting layers.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


###############################################################################
# Artifact
###############################################################################


@dataclass(frozen=True, slots=True)
class Artifact:
    """
    Canonical representation of an assessment artifact.

    An artifact identifies a generated file together with optional metadata
    describing its role in the ScopeForgeX workflow.
    """

    path: str
    artifact_type: str = "file"
    description: str = ""
    tool: str | None = None
    stage: int | None = None
    exists: bool = True

    ###########################################################################
    # Construction
    ###########################################################################

    @classmethod
    def from_path(
        cls,
        path: str | Path,
        *,
        artifact_type: str = "file",
        description: str = "",
        tool: str | None = None,
        stage: int | None = None,
    ) -> "Artifact":
        """
        Create an Artifact from a filesystem path.
        """

        resolved = Path(path)

        return cls(
            path=str(resolved),
            artifact_type=artifact_type,
            description=description,
            tool=tool,
            stage=stage,
            exists=resolved.exists(),
        )

    ###########################################################################
    # Filesystem Helpers
    ###########################################################################

    def as_path(
        self,
    ) -> Path:
        """
        Return the artifact path as a Path object.
        """

        return Path(
            self.path
        )

    def refresh(
        self,
    ) -> "Artifact":
        """
        Return a copy with the current filesystem existence state.
        """

        return Artifact(
            path=self.path,
            artifact_type=self.artifact_type,
            description=self.description,
            tool=self.tool,
            stage=self.stage,
            exists=self.as_path().exists(),
        )

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serialization-friendly artifact representation.
        """

        return {
            "path": self.path,
            "artifact_type": self.artifact_type,
            "description": self.description,
            "tool": self.tool,
            "stage": self.stage,
            "exists": self.exists,
        }

    def __str__(
        self,
    ) -> str:
        """
        Return the artifact filesystem path.
        """

        return self.path
