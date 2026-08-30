"""
ScopeForgeX Evidence Store
==========================

Persistent evidence storage for ScopeForgeX assessments.

Responsibilities
----------------

- Store raw and normalized evidence artifacts.
- Keep evidence associated with an assessment.
- Preserve tool provenance.
- Generate deterministic evidence identifiers.
- Prevent accidental overwriting of unrelated evidence.
- Provide safe retrieval and listing of stored evidence.
- Keep evidence storage independent from findings, correlation, and reporting.

The evidence store does not:

- Execute external tools.
- Perform network requests.
- Generate findings.
- Classify vulnerabilities.
- Correlate findings.
- Deduplicate findings.
- Modify finding severity or confidence.

Architecture
------------

Tool
    |
    v
Execution Layer
    |
    v
Raw Artifact
    |
    v
EvidenceStore
    |
    +--> raw/
    +--> normalized/
    +--> metadata/
    |
    v
Finding / Correlation / Reporting

Evidence is an observation produced during an assessment. It is preserved
independently from the normalized Finding model so that the original
assessment material remains available for investigation and reporting.

v1.2.0
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


###############################################################################
# Constants
###############################################################################


EVIDENCE_VERSION = "1.0"

RAW_EVIDENCE = "raw"
NORMALIZED_EVIDENCE = "normalized"
METADATA_EVIDENCE = "metadata"


###############################################################################
# Evidence Artifact
###############################################################################


@dataclass(slots=True)
class EvidenceArtifact:
    """
    Metadata describing a stored evidence artifact.

    The artifact contains references to the stored material rather than
    duplicating the evidence content in memory.
    """

    evidence_id: str

    assessment_id: str

    artifact_type: str

    source_tool: str = ""

    filename: str = ""

    relative_path: str = ""

    media_type: str = "application/octet-stream"

    size: int = 0

    sha256: str = ""

    created_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @property
    def path(self) -> str:
        """Return the stored artifact path."""

        return self.relative_path

    def as_dict(self) -> dict[str, Any]:
        """Serialize the evidence artifact."""

        return {
            "evidence_id": self.evidence_id,
            "assessment_id": self.assessment_id,
            "artifact_type": self.artifact_type,
            "source_tool": self.source_tool,
            "filename": self.filename,
            "relative_path": self.relative_path,
            "media_type": self.media_type,
            "size": self.size,
            "sha256": self.sha256,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
    ) -> "EvidenceArtifact":
        """Create an EvidenceArtifact from serialized data."""

        return cls(
            evidence_id=str(
                data.get(
                    "evidence_id",
                    "",
                )
            ),
            assessment_id=str(
                data.get(
                    "assessment_id",
                    "",
                )
            ),
            artifact_type=str(
                data.get(
                    "artifact_type",
                    "",
                )
            ),
            source_tool=str(
                data.get(
                    "source_tool",
                    "",
                )
            ),
            filename=str(
                data.get(
                    "filename",
                    "",
                )
            ),
            relative_path=str(
                data.get(
                    "relative_path",
                    "",
                )
            ),
            media_type=str(
                data.get(
                    "media_type",
                    "application/octet-stream",
                )
            ),
            size=int(
                data.get(
                    "size",
                    0,
                )
                or 0
            ),
            sha256=str(
                data.get(
                    "sha256",
                    "",
                )
            ),
            created_at=str(
                data.get(
                    "created_at",
                    "",
                )
            ),
            metadata=dict(
                data.get(
                    "metadata",
                    {},
                )
                or {}
            ),
        )


###############################################################################
# Evidence Store
###############################################################################


class EvidenceStore:
    """
    Store and retrieve ScopeForgeX evidence artifacts.

    Storage layout:

        <root>/
        ├── raw/
        │   └── <tool>/
        ├── normalized/
        │   └── <tool>/
        └── metadata/
            └── evidence.json

    The store never interprets the contents of evidence. It only preserves
    them and records metadata necessary for traceability.
    """

    name = "evidence_store"

    description = (
        "Persistent storage for raw and normalized ScopeForgeX evidence."
    )

    def __init__(
        self,
        root: str | Path,
        assessment_id: str = "",
    ) -> None:
        """
        Initialize an evidence store.

        Args:
            root:
                Root directory used for evidence storage.

            assessment_id:
                Optional assessment identifier associated with the store.
        """

        self.root = Path(
            root
        )

        self.assessment_id = (
            str(
                assessment_id
            ).strip()
        )

        self.raw_root = (
            self.root / RAW_EVIDENCE
        )

        self.normalized_root = (
            self.root / NORMALIZED_EVIDENCE
        )

        self.metadata_root = (
            self.root / METADATA_EVIDENCE
        )

        self.index_path = (
            self.metadata_root
            / "evidence.json"
        )

        self._artifacts: dict[
            str,
            EvidenceArtifact,
        ] = {}

        self._load_index()

    ###########################################################################
    # Initialization
    ###########################################################################

    def initialize(self) -> None:
        """Create the evidence-store directory structure."""

        self.raw_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.normalized_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.metadata_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._save_index()

    ###########################################################################
    # Raw Evidence
    ###########################################################################

    def store_raw(
        self,
        source_tool: str,
        content: str | bytes,
        *,
        filename: str | None = None,
        media_type: str = "text/plain",
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceArtifact:
        """
        Store raw tool output.

        Args:
            source_tool:
                Tool that produced the evidence.

            content:
                Raw output as text or bytes.

            filename:
                Optional filename. A deterministic name is generated when
                omitted.

            media_type:
                MIME type describing the artifact.

            metadata:
                Optional artifact metadata.

        Returns:
            Stored EvidenceArtifact.
        """

        return self._store_content(
            artifact_type=RAW_EVIDENCE,
            source_tool=source_tool,
            content=content,
            filename=filename,
            media_type=media_type,
            metadata=metadata,
        )

    ###########################################################################
    # Normalized Evidence
    ###########################################################################

    def store_normalized(
        self,
        source_tool: str,
        content: str | bytes | Mapping[str, Any] | list[Any],
        *,
        filename: str | None = None,
        media_type: str = "application/json",
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceArtifact:
        """
        Store normalized collector/analyzer output.

        Structured mappings and lists are serialized as deterministic JSON.
        """

        if isinstance(
            content,
            (Mapping, list),
        ):
            content = json.dumps(
                content,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )

        return self._store_content(
            artifact_type=NORMALIZED_EVIDENCE,
            source_tool=source_tool,
            content=content,
            filename=filename,
            media_type=media_type,
            metadata=metadata,
        )

    ###########################################################################
    # Generic Storage
    ###########################################################################

    def store_file(
        self,
        source_tool: str,
        source_path: str | Path,
        *,
        artifact_type: str = RAW_EVIDENCE,
        filename: str | None = None,
        media_type: str = "application/octet-stream",
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceArtifact:
        """
        Copy an existing file into the evidence store.

        The source file is never modified or deleted.
        """

        source = Path(
            source_path
        )

        if not source.is_file():
            raise FileNotFoundError(
                f"Evidence source file does not exist: {source}"
            )

        if artifact_type not in {
            RAW_EVIDENCE,
            NORMALIZED_EVIDENCE,
        }:
            raise ValueError(
                "artifact_type must be 'raw' or 'normalized'."
            )

        destination_root = self._artifact_root(
            artifact_type,
            source_tool,
        )

        destination_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        destination_name = (
            filename
            if filename
            else source.name
        )

        safe_name = self._safe_filename(
            destination_name
        )

        destination = self._unique_destination(
            destination_root,
            safe_name,
        )

        shutil.copy2(
            source,
            destination,
        )

        artifact = self._register_file(
            artifact_type=artifact_type,
            source_tool=source_tool,
            path=destination,
            media_type=media_type,
            metadata=metadata,
        )

        return artifact

    ###########################################################################
    # Retrieval
    ###########################################################################

    def get(
        self,
        evidence_id: str,
    ) -> EvidenceArtifact | None:
        """Return an evidence artifact by identifier."""

        return self._artifacts.get(
            str(
                evidence_id
            ).strip()
        )

    def require(
        self,
        evidence_id: str,
    ) -> EvidenceArtifact:
        """Return an evidence artifact or raise KeyError."""

        artifact = self.get(
            evidence_id
        )

        if artifact is None:
            raise KeyError(
                f"Evidence artifact not found: {evidence_id}"
            )

        return artifact

    def list(
        self,
        *,
        artifact_type: str | None = None,
        source_tool: str | None = None,
    ) -> list[EvidenceArtifact]:
        """
        List stored evidence artifacts.

        Results are deterministic and sorted by evidence identifier.
        """

        artifacts = list(
            self._artifacts.values()
        )

        if artifact_type:
            normalized_type = (
                artifact_type.strip().lower()
            )

            artifacts = [
                artifact
                for artifact in artifacts
                if artifact.artifact_type.lower()
                == normalized_type
            ]

        if source_tool:
            normalized_tool = (
                source_tool.strip().lower()
            )

            artifacts = [
                artifact
                for artifact in artifacts
                if artifact.source_tool.lower()
                == normalized_tool
            ]

        return sorted(
            artifacts,
            key=lambda artifact: artifact.evidence_id,
        )

    def read(
        self,
        evidence_id: str,
    ) -> bytes:
        """
        Read the stored bytes of an evidence artifact.
        """

        artifact = self.require(
            evidence_id
        )

        path = self.root / artifact.relative_path

        if not path.is_file():
            raise FileNotFoundError(
                f"Stored evidence file is missing: {path}"
            )

        return path.read_bytes()

    def read_text(
        self,
        evidence_id: str,
        *,
        encoding: str = "utf-8",
    ) -> str:
        """Read an evidence artifact as text."""

        return self.read(
            evidence_id
        ).decode(
            encoding
        )

    ###########################################################################
    # Verification
    ###########################################################################

    def verify(
        self,
        evidence_id: str,
    ) -> bool:
        """
        Verify the SHA-256 digest of a stored evidence artifact.
        """

        artifact = self.require(
            evidence_id
        )

        path = self.root / artifact.relative_path

        if not path.is_file():
            return False

        digest = self._sha256_file(
            path
        )

        return digest == artifact.sha256

    ###########################################################################
    # Removal
    ###########################################################################

    def remove(
        self,
        evidence_id: str,
    ) -> bool:
        """
        Remove an evidence artifact and its metadata.

        Returns:
            True when an artifact existed and was removed.
        """

        artifact = self._artifacts.pop(
            str(
                evidence_id
            ).strip(),
            None,
        )

        if artifact is None:
            return False

        path = self.root / artifact.relative_path

        if path.is_file():
            path.unlink()

        self._save_index()

        return True

    ###########################################################################
    # Serialization
    ###########################################################################

    def as_dict(self) -> dict[str, Any]:
        """Serialize the complete evidence index."""

        return {
            "version": EVIDENCE_VERSION,
            "assessment_id": self.assessment_id,
            "root": str(
                self.root
            ),
            "artifacts": [
                artifact.as_dict()
                for artifact in self.list()
            ],
        }

    def save(self) -> None:
        """Persist the evidence index."""

        self._save_index()

    ###########################################################################
    # Internal Storage
    ###########################################################################

    def _store_content(
        self,
        *,
        artifact_type: str,
        source_tool: str,
        content: str | bytes,
        filename: str | None,
        media_type: str,
        metadata: Mapping[str, Any] | None,
    ) -> EvidenceArtifact:
        """Store in-memory evidence content."""

        if artifact_type not in {
            RAW_EVIDENCE,
            NORMALIZED_EVIDENCE,
        }:
            raise ValueError(
                "Unsupported evidence artifact type."
            )

        tool = (
            str(
                source_tool
            ).strip()
        )

        if not tool:
            raise ValueError(
                "source_tool is required."
            )

        if isinstance(
            content,
            str,
        ):
            data = content.encode(
                "utf-8"
            )
        elif isinstance(
            content,
            bytes,
        ):
            data = content
        else:
            raise TypeError(
                "Evidence content must be str or bytes."
            )

        digest = hashlib.sha256(
            data
        ).hexdigest()

        destination_root = self._artifact_root(
            artifact_type,
            tool,
        )

        destination_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        if filename:
            safe_name = self._safe_filename(
                filename
            )
        else:
            safe_name = (
                f"{digest[:16]}.bin"
            )

        destination = self._unique_destination(
            destination_root,
            safe_name,
        )

        destination.write_bytes(
            data
        )

        return self._register_file(
            artifact_type=artifact_type,
            source_tool=tool,
            path=destination,
            media_type=media_type,
            metadata=metadata,
            digest=digest,
        )

    def _register_file(
        self,
        *,
        artifact_type: str,
        source_tool: str,
        path: Path,
        media_type: str,
        metadata: Mapping[str, Any] | None,
        digest: str | None = None,
    ) -> EvidenceArtifact:
        """Create and register metadata for a stored file."""

        file_digest = (
            digest
            if digest is not None
            else self._sha256_file(
                path
            )
        )

        evidence_id = self._generate_id(
            artifact_type,
            source_tool,
            file_digest,
        )

        relative_path = path.relative_to(
            self.root
        ).as_posix()

        artifact = EvidenceArtifact(
            evidence_id=evidence_id,
            assessment_id=self.assessment_id,
            artifact_type=artifact_type,
            source_tool=source_tool,
            filename=path.name,
            relative_path=relative_path,
            media_type=media_type,
            size=path.stat().st_size,
            sha256=file_digest,
            metadata=dict(
                metadata
                or {}
            ),
        )

        self._artifacts[
            evidence_id
        ] = artifact

        self._save_index()

        return artifact

    ###########################################################################
    # Index
    ###########################################################################

    def _load_index(self) -> None:
        """Load the evidence index if it exists."""

        if not self.index_path.is_file():
            return

        try:
            payload = json.loads(
                self.index_path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ):
            return

        artifacts = payload.get(
            "artifacts",
            [],
        )

        if not isinstance(
            artifacts,
            list,
        ):
            return

        for item in artifacts:

            if not isinstance(
                item,
                Mapping,
            ):
                continue

            artifact = EvidenceArtifact.from_dict(
                item
            )

            if artifact.evidence_id:
                self._artifacts[
                    artifact.evidence_id
                ] = artifact

        stored_assessment = str(
            payload.get(
                "assessment_id",
                "",
            )
        ).strip()

        if (
            not self.assessment_id
            and stored_assessment
        ):
            self.assessment_id = (
                stored_assessment
            )

    def _save_index(self) -> None:
        """Persist the evidence index atomically."""

        self.metadata_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = self.as_dict()

        temporary = self.index_path.with_suffix(
            ".tmp"
        )

        temporary.write_text(
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        temporary.replace(
            self.index_path
        )

    ###########################################################################
    # Paths
    ###########################################################################

    def _artifact_root(
        self,
        artifact_type: str,
        source_tool: str,
    ) -> Path:
        """Return the storage directory for an artifact."""

        if artifact_type == RAW_EVIDENCE:
            root = self.raw_root
        elif artifact_type == NORMALIZED_EVIDENCE:
            root = self.normalized_root
        else:
            raise ValueError(
                f"Unsupported artifact type: {artifact_type}"
            )

        return (
            root
            / self._safe_component(
                source_tool
            )
        )

    @staticmethod
    def _safe_component(
        value: str,
    ) -> str:
        """Convert a value into a safe filesystem component."""

        normalized = str(
            value
        ).strip()

        if not normalized:
            return "unknown"

        characters: list[str] = []

        for character in normalized:
            if (
                character.isalnum()
                or character
                in {
                    "-",
                    "_",
                    ".",
                }
            ):
                characters.append(
                    character
                )
            else:
                characters.append(
                    "_"
                )

        result = "".join(
            characters
        ).strip(
            "._"
        )

        return result or "unknown"

    @classmethod
    def _safe_filename(
        cls,
        filename: str,
    ) -> str:
        """Sanitize a supplied evidence filename."""

        name = Path(
            str(
                filename
            )
        ).name

        return cls._safe_component(
            name
        )

    @staticmethod
    def _unique_destination(
        root: Path,
        filename: str,
    ) -> Path:
        """
        Return a non-conflicting destination path.

        Existing files are never overwritten.
        """

        candidate = root / filename

        if not candidate.exists():
            return candidate

        stem = candidate.stem
        suffix = candidate.suffix

        counter = 2

        while True:
            candidate = (
                root
                / f"{stem}-{counter}{suffix}"
            )

            if not candidate.exists():
                return candidate

            counter += 1

    ###########################################################################
    # Identity / Hashing
    ###########################################################################

    def _generate_id(
        self,
        artifact_type: str,
        source_tool: str,
        digest: str,
    ) -> str:
        """
        Generate a deterministic evidence identifier.

        The assessment identifier is included so identical evidence generated
        during different assessments remains independently addressable.
        """

        identity = "|".join(
            (
                self.assessment_id,
                artifact_type,
                source_tool.strip().lower(),
                digest,
            )
        )

        fingerprint = hashlib.sha256(
            identity.encode(
                "utf-8"
            )
        ).hexdigest()

        return (
            f"EV-{fingerprint[:16].upper()}"
        )

    @staticmethod
    def _sha256_file(
        path: Path,
    ) -> str:
        """Calculate the SHA-256 digest of a file."""

        digest = hashlib.sha256()

        with path.open(
            "rb"
        ) as handle:

            for chunk in iter(
                lambda: handle.read(
                    1024 * 1024
                ),
                b"",
            ):
                digest.update(
                    chunk
                )

        return digest.hexdigest()


###############################################################################
# Convenience API
###############################################################################


def create_evidence_store(
    root: str | Path,
    assessment_id: str = "",
) -> EvidenceStore:
    """
    Create and initialize an EvidenceStore.
    """

    store = EvidenceStore(
        root=root,
        assessment_id=assessment_id,
    )

    store.initialize()

    return store


###############################################################################
# Public API
###############################################################################


__all__ = [
    "EVIDENCE_VERSION",
    "RAW_EVIDENCE",
    "NORMALIZED_EVIDENCE",
    "METADATA_EVIDENCE",
    "EvidenceArtifact",
    "EvidenceStore",
    "create_evidence_store",
]
