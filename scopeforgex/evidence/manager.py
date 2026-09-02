"""
ScopeForgeX Evidence Manager
============================

High-level evidence orchestration layer for ScopeForgeX.

Responsibilities
----------------

- Coordinate evidence persistence through EvidenceStore.
- Provide a stable interface for storing raw tool output.
- Persist normalized findings and correlated results.
- Attach persisted evidence references to Findings.
- Preserve evidence provenance and assessment context.
- Keep evidence handling independent from tool execution.
- Keep evidence handling independent from finding generation.
- Keep evidence handling independent from correlation and deduplication.
- Never perform network requests.
- Never execute external security tools.
- Never invent evidence.

Architecture
------------

Tool / Collector / Analyzer
            |
            v
    EvidenceManager
            |
            v
      EvidenceStore
            |
    +-------+--------+
    |       |        |
    v       v        v
   RAW   FINDINGS  CORRELATED
    |       |        |
    +-------+--------+
            |
            v
        Reporting

The EvidenceManager is intentionally a coordination layer.

EvidenceStore owns persistence mechanics such as:

- filesystem layout
- serialization
- hashing
- integrity verification
- artifact identifiers
- artifact retrieval

EvidenceManager owns workflow-level evidence operations such as:

- associating evidence with a finding
- persisting batches of findings
- persisting correlated groups
- storing raw execution artifacts
- producing evidence references for downstream consumers

The manager does not replace EvidenceStore.

Evidence is never treated as proof of vulnerability confirmation merely because
it has been persisted. Finding confidence and validation remain separate
concerns.

v1.3.0
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scopeforgex.findings.model import Finding

from .store import EvidenceStore


###############################################################################
# Constants
###############################################################################


RAW_LAYER = "raw"
FINDINGS_LAYER = "findings"
CORRELATED_LAYER = "correlated"


###############################################################################
# Evidence Reference
###############################################################################


@dataclass(slots=True)
class EvidenceReference:
    """
    Reference to persisted ScopeForgeX evidence.

    The reference deliberately contains metadata rather than duplicating the
    persisted evidence itself.

    This allows Findings and reports to point back to immutable evidence
    artifacts without embedding large raw tool outputs directly into every
    object.
    """

    evidence_id: str

    layer: str

    path: str = ""

    sha256: str | None = None

    source_tool: str | None = None

    finding_id: str | None = None

    created_at: datetime = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(
        self,
    ) -> None:
        """
        Normalize the evidence reference.
        """

        self.evidence_id = str(
            self.evidence_id
        ).strip()

        if not self.evidence_id:
            raise ValueError(
                "EvidenceReference requires evidence_id."
            )

        self.layer = str(
            self.layer
        ).strip().lower()

        if self.layer not in {
            RAW_LAYER,
            FINDINGS_LAYER,
            CORRELATED_LAYER,
        }:
            raise ValueError(
                f"Unsupported evidence layer: {self.layer}"
            )

        self.path = str(
            self.path
        ).strip()

        if self.sha256 is not None:
            self.sha256 = str(
                self.sha256
            ).strip() or None

        if self.source_tool is not None:
            self.source_tool = str(
                self.source_tool
            ).strip() or None

        if self.finding_id is not None:
            self.finding_id = str(
                self.finding_id
            ).strip() or None

        if not isinstance(
            self.metadata,
            dict,
        ):
            self.metadata = dict(
                self.metadata
            )

        if not isinstance(
            self.created_at,
            datetime,
        ):
            self.created_at = datetime.now(
                timezone.utc
            )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the evidence reference.
        """

        return {
            "evidence_id": self.evidence_id,
            "layer": self.layer,
            "path": self.path,
            "sha256": self.sha256,
            "source_tool": self.source_tool,
            "finding_id": self.finding_id,
            "created_at": self.created_at.isoformat(),
            "metadata": deepcopy(
                self.metadata
            ),
        }


###############################################################################
# Evidence Manager
###############################################################################


class EvidenceManager:
    """
    Coordinate ScopeForgeX evidence persistence.

    EvidenceManager intentionally delegates filesystem and integrity behavior
    to EvidenceStore.

    It provides the higher-level interface required by the assessment
    workflow.

    Evidence storage is assessment/run scoped. Callers should normally create
    the manager with the current workflow run output directory.
    """

    name = "evidence_manager"

    description = (
        "Coordinate raw, normalized, and correlated evidence through "
        "the canonical ScopeForgeX EvidenceStore."
    )

    def __init__(
        self,
        store: EvidenceStore | None = None,
        root: str | Path | None = None,
    ) -> None:
        """
        Initialize the evidence manager.

        Args:
            store:
                Existing EvidenceStore instance.

            root:
                Evidence root used when creating an EvidenceStore.

        Raises:
            ValueError:
                If both ``store`` and ``root`` are supplied.

            TypeError:
                If neither ``store`` nor ``root`` is supplied.
        """

        if (
            store is not None
            and root is not None
        ):
            raise ValueError(
                "Provide either store or root, not both."
            )

        if store is not None:

            if not isinstance(
                store,
                EvidenceStore,
            ):
                raise TypeError(
                    "store must be an EvidenceStore."
                )

            self.store = store
            return

        if root is None:
            raise TypeError(
                "EvidenceManager requires either an EvidenceStore "
                "or an evidence root path."
            )

        self.store = EvidenceStore(
            Path(
                root
            )
        )

    ###########################################################################
    # Raw Evidence
    ###########################################################################

    def store_raw(
        self,
        source_tool: str,
        data: Any,
        *,
        target: str | None = None,
        filename: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceReference:
        """
        Persist raw tool output.

        Raw output is preserved exactly as supplied to EvidenceStore.
        """

        tool = self._required_text(
            source_tool,
            "source_tool",
        )

        store_result = self._store_raw(
            tool,
            data,
            target=target,
            filename=filename,
            metadata=metadata,
        )

        return self._reference_from_result(
            store_result,
            layer=RAW_LAYER,
            source_tool=tool,
            metadata=metadata,
        )

    def store_raw_batch(
        self,
        artifacts: Iterable[Mapping[str, Any]],
    ) -> list[EvidenceReference]:
        """
        Persist multiple raw evidence artifacts.

        Each artifact mapping must contain:

            source_tool
            data

        Optional fields:

            target
            filename
            metadata
        """

        references: list[EvidenceReference] = []

        for artifact in artifacts:

            if not isinstance(
                artifact,
                Mapping,
            ):
                raise TypeError(
                    "Raw evidence batch items must be mappings."
                )

            if "data" not in artifact:
                raise ValueError(
                    "Raw evidence artifact is missing 'data'."
                )

            references.append(
                self.store_raw(
                    artifact.get(
                        "source_tool",
                        "",
                    ),
                    artifact[
                        "data"
                    ],
                    target=artifact.get(
                        "target"
                    ),
                    filename=artifact.get(
                        "filename"
                    ),
                    metadata=artifact.get(
                        "metadata"
                    ),
                )
            )

        return references

    ###########################################################################
    # Finding Evidence
    ###########################################################################

    def store_finding(
        self,
        finding: Finding,
        *,
        raw_evidence_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceReference:
        """
        Persist a normalized Finding as evidence.

        The Finding itself remains the canonical assessment object.
        """

        self._require_finding(
            finding
        )

        finding_data = self._serialize_finding(
            finding
        )

        evidence_metadata = self._merge_metadata(
            metadata,
            {
                "finding_id": finding.finding_id,
                "source_tool": finding.source_tool,
            },
        )

        if raw_evidence_id:

            evidence_metadata[
                "raw_evidence_id"
            ] = str(
                raw_evidence_id
            ).strip()

        store_result = self._store_normalized(
            finding_data,
            finding_id=finding.finding_id,
            metadata=evidence_metadata,
        )

        reference = self._reference_from_result(
            store_result,
            layer=FINDINGS_LAYER,
            source_tool=(
                finding.source_tool
                or None
            ),
            finding_id=finding.finding_id,
            metadata=evidence_metadata,
        )

        self.attach_reference(
            finding,
            reference,
        )

        return reference

    def store_findings(
        self,
        findings: Iterable[Finding],
        *,
        raw_evidence_ids: Mapping[str, str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[EvidenceReference]:
        """
        Persist a collection of normalized Findings.
        """

        references: list[EvidenceReference] = []

        raw_ids = (
            dict(
                raw_evidence_ids
            )
            if raw_evidence_ids is not None
            else {}
        )

        for finding in findings:

            raw_evidence_id = raw_ids.get(
                finding.finding_id
            )

            references.append(
                self.store_finding(
                    finding,
                    raw_evidence_id=raw_evidence_id,
                    metadata=metadata,
                )
            )

        return references

    ###########################################################################
    # Correlated Evidence
    ###########################################################################

    def store_correlated(
        self,
        groups: Iterable[Any],
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> list[EvidenceReference]:
        """
        Persist correlated finding groups.

        Correlation objects are serialized but never converted into Findings.

        Objects exposing ``as_dict()`` and ordinary mappings are supported.
        """

        references: list[EvidenceReference] = []

        for group in groups:

            serialized = self._serialize_object(
                group
            )

            group_id = self._object_identifier(
                group,
                "group_id",
            )

            group_metadata = self._merge_metadata(
                metadata,
                {
                    "group_id": group_id,
                }
                if group_id
                else {},
            )

            store_result = self._store_correlated(
                serialized,
                group_id=group_id,
                metadata=group_metadata,
            )

            references.append(
                self._reference_from_result(
                    store_result,
                    layer=CORRELATED_LAYER,
                    source_tool="scopeforgex",
                    metadata=group_metadata,
                )
            )

        return references

    ###########################################################################
    # Evidence Attachment
    ###########################################################################

    @staticmethod
    def attach_reference(
        finding: Finding,
        reference: EvidenceReference,
    ) -> Finding:
        """
        Attach an EvidenceReference to a Finding.

        Existing Finding evidence is preserved.

        Persisted artifact references are stored under Finding.metadata.
        """

        if not isinstance(
            finding,
            Finding,
        ):
            raise TypeError(
                "finding must be a Finding."
            )

        if not isinstance(
            reference,
            EvidenceReference,
        ):
            raise TypeError(
                "reference must be an EvidenceReference."
            )

        references = finding.metadata.get(
            "evidence_references"
        )

        if references is None:

            references = []

        elif not isinstance(
            references,
            list,
        ):

            references = [
                references
            ]

        serialized = reference.as_dict()

        if not EvidenceManager._contains_reference(
            references,
            reference.evidence_id,
        ):

            references.append(
                serialized
            )

        finding.metadata[
            "evidence_references"
        ] = references

        return finding

    @staticmethod
    def _contains_reference(
        references: list[Any],
        evidence_id: str,
    ) -> bool:
        """
        Determine whether an evidence reference is already attached.
        """

        for reference in references:

            if isinstance(
                reference,
                Mapping,
            ):

                existing_id = str(
                    reference.get(
                        "evidence_id",
                        "",
                    )
                ).strip()

                if existing_id == evidence_id:
                    return True

            elif str(
                reference
            ).strip() == evidence_id:

                return True

        return False

    ###########################################################################
    # Retrieval
    ###########################################################################

    def get(
        self,
        evidence_id: str,
    ) -> Any:
        """
        Retrieve persisted evidence through EvidenceStore.
        """

        identifier = self._required_text(
            evidence_id,
            "evidence_id",
        )

        return self._store_get(
            identifier
        )

    def exists(
        self,
        evidence_id: str,
    ) -> bool:
        """
        Determine whether an evidence artifact exists.
        """

        identifier = self._required_text(
            evidence_id,
            "evidence_id",
        )

        method = getattr(
            self.store,
            "exists",
            None,
        )

        if method is None:

            try:

                self._store_get(
                    identifier
                )

            except (
                FileNotFoundError,
                KeyError,
            ):

                return False

            return True

        return bool(
            method(
                identifier
            )
        )

    def verify(
        self,
        evidence_id: str,
    ) -> bool:
        """
        Verify persisted evidence integrity through EvidenceStore.
        """

        identifier = self._required_text(
            evidence_id,
            "evidence_id",
        )

        method = getattr(
            self.store,
            "verify",
            None,
        )

        if method is None:
            raise AttributeError(
                "EvidenceStore does not expose verify()."
            )

        return bool(
            method(
                identifier
            )
        )

    ###########################################################################
    # Finding Evidence Resolution
    ###########################################################################

    def get_finding_evidence(
        self,
        finding: Finding,
    ) -> list[EvidenceReference]:
        """
        Return persisted evidence references attached to a Finding.
        """

        self._require_finding(
            finding
        )

        raw_references = finding.metadata.get(
            "evidence_references",
            [],
        )

        if not isinstance(
            raw_references,
            list,
        ):

            raw_references = [
                raw_references
            ]

        references: list[EvidenceReference] = []

        for item in raw_references:

            if isinstance(
                item,
                EvidenceReference,
            ):

                references.append(
                    item
                )

                continue

            if not isinstance(
                item,
                Mapping,
            ):
                continue

            evidence_id = str(
                item.get(
                    "evidence_id",
                    "",
                )
            ).strip()

            if not evidence_id:
                continue

            created_at = self._parse_timestamp(
                item.get(
                    "created_at"
                )
            )

            references.append(
                EvidenceReference(
                    evidence_id=evidence_id,
                    layer=str(
                        item.get(
                            "layer",
                            FINDINGS_LAYER,
                        )
                    ),
                    path=str(
                        item.get(
                            "path",
                            "",
                        )
                    ),
                    sha256=item.get(
                        "sha256"
                    ),
                    source_tool=item.get(
                        "source_tool"
                    ),
                    finding_id=item.get(
                        "finding_id"
                    ),
                    created_at=created_at,
                    metadata=dict(
                        item.get(
                            "metadata",
                            {},
                        )
                        or {}
                    ),
                )
            )

        return references

    ###########################################################################
    # Serialization
    ###########################################################################

    @staticmethod
    def _serialize_finding(
        finding: Finding,
    ) -> dict[str, Any]:
        """
        Serialize a Finding using its canonical representation.
        """

        if hasattr(
            finding,
            "as_dict",
        ):

            serialized = finding.as_dict()

            if isinstance(
                serialized,
                Mapping,
            ):

                return deepcopy(
                    dict(
                        serialized
                    )
                )

        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "target": finding.target,
            "host": finding.host,
            "port": finding.port,
            "url": finding.url,
            "parameter": finding.parameter,
            "description": finding.description,
            "evidence": deepcopy(
                finding.evidence
            ),
            "source_tool": finding.source_tool,
            "detection_method": finding.detection_method,
            "timestamp": (
                finding.timestamp.isoformat()
                if finding.timestamp is not None
                else None
            ),
            "cwe": finding.cwe,
            "cve": finding.cve,
            "references": list(
                finding.references
            ),
            "impact": finding.impact,
            "remediation": finding.remediation,
            "status": finding.status,
            "metadata": deepcopy(
                finding.metadata
            ),
        }

    @staticmethod
    def _serialize_object(
        value: Any,
    ) -> Any:
        """
        Serialize an arbitrary supported evidence object.
        """

        if hasattr(
            value,
            "as_dict",
        ):

            return deepcopy(
                value.as_dict()
            )

        if isinstance(
            value,
            Mapping,
        ):

            return deepcopy(
                dict(
                    value
                )
            )

        if isinstance(
            value,
            (list, tuple),
        ):

            return [
                EvidenceManager._serialize_object(
                    item
                )
                for item in value
            ]

        return deepcopy(
            value
        )

    ###########################################################################
    # Store Compatibility Layer
    ###########################################################################

    def _store_raw(
        self,
        source_tool: str,
        data: Any,
        *,
        target: str | None,
        filename: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> Any:
        """
        Call the canonical EvidenceStore raw-artifact API.

        The canonical store uses ``content``. Compatibility with older
        implementations accepting ``data`` is retained when supported.
        """

        method = self._first_method(
            "store_raw",
            "save_raw",
            "write_raw",
        )

        if method is None:
            raise AttributeError(
                "EvidenceStore does not expose a raw evidence storage method."
            )

        kwargs: dict[str, Any] = {}

        self._add_if_supported(
            method,
            kwargs,
            "source_tool",
            source_tool,
        )

        self._add_if_supported(
            method,
            kwargs,
            "content",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "data",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "target",
            target,
        )

        self._add_if_supported(
            method,
            kwargs,
            "filename",
            filename,
        )

        self._add_if_supported(
            method,
            kwargs,
            "metadata",
            metadata,
        )

        return method(
            **kwargs
        )

    def _store_normalized(
        self,
        data: Mapping[str, Any],
        *,
        finding_id: str,
        metadata: Mapping[str, Any] | None,
    ) -> Any:
        """
        Persist normalized finding data.
        """

        method = self._first_method(
            "store_normalized",
            "save_normalized",
            "write_normalized",
        )

        if method is None:
            raise AttributeError(
                "EvidenceStore does not expose a normalized evidence "
                "storage method."
            )

        source_tool = ""

        if metadata is not None:

            source_tool = str(
                metadata.get(
                    "source_tool",
                    "",
                )
            ).strip()

        if not source_tool:
            source_tool = "scopeforgex"

        kwargs: dict[str, Any] = {}

        self._add_if_supported(
            method,
            kwargs,
            "source_tool",
            source_tool,
        )

        self._add_if_supported(
            method,
            kwargs,
            "content",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "data",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "filename",
            f"{finding_id}.json",
        )

        self._add_if_supported(
            method,
            kwargs,
            "finding_id",
            finding_id,
        )

        self._add_if_supported(
            method,
            kwargs,
            "metadata",
            metadata,
        )

        return method(
            **kwargs
        )

    def _store_correlated(
        self,
        data: Any,
        *,
        group_id: str | None,
        metadata: Mapping[str, Any] | None,
    ) -> Any:
        """
        Persist correlated assessment data.

        The canonical EvidenceStore correlated API requires:

            source_tool
            content

        Correlation is generated by ScopeForgeX, so ``scopeforgex`` is the
        default provenance value.
        """

        method = self._first_method(
            "store_correlated",
            "save_correlated",
            "write_correlated",
        )

        if method is None:
            raise AttributeError(
                "EvidenceStore does not expose correlated evidence storage."
            )

        source_tool = "scopeforgex"

        if metadata is not None:

            configured_source = metadata.get(
                "source_tool"
            )

            if configured_source is not None:

                normalized_source = str(
                    configured_source
                ).strip()

                if normalized_source:
                    source_tool = normalized_source

        kwargs: dict[str, Any] = {}

        self._add_if_supported(
            method,
            kwargs,
            "source_tool",
            source_tool,
        )

        self._add_if_supported(
            method,
            kwargs,
            "content",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "data",
            data,
        )

        self._add_if_supported(
            method,
            kwargs,
            "filename",
            (
                f"{group_id}.json"
                if group_id
                else None
            ),
        )

        self._add_if_supported(
            method,
            kwargs,
            "group_id",
            group_id,
        )

        self._add_if_supported(
            method,
            kwargs,
            "metadata",
            metadata,
        )

        return method(
            **kwargs
        )

    def _store_get(
        self,
        evidence_id: str,
    ) -> Any:
        """
        Retrieve an artifact through EvidenceStore.
        """

        method = self._first_method(
            "get",
            "retrieve",
            "load",
            "read",
        )

        if method is None:
            raise AttributeError(
                "EvidenceStore does not expose an evidence retrieval method."
            )

        return method(
            evidence_id
        )

    def _first_method(
        self,
        *names: str,
    ) -> Any:
        """
        Return the first callable method supported by EvidenceStore.
        """

        for name in names:

            method = getattr(
                self.store,
                name,
                None,
            )

            if callable(
                method
            ):
                return method

        return None

    @staticmethod
    def _add_if_supported(
        method: Any,
        kwargs: dict[str, Any],
        name: str,
        value: Any,
    ) -> None:
        """
        Add a keyword argument only when the target method accepts it.
        """

        if value is None:
            return

        try:

            import inspect

            signature = inspect.signature(
                method
            )

            parameters = signature.parameters

            if (
                name in parameters
                or any(
                    parameter.kind
                    == inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
            ):

                kwargs[
                    name
                ] = value

        except (
            TypeError,
            ValueError,
        ):

            return

    ###########################################################################
    # Result Normalization
    ###########################################################################

    @classmethod
    def _reference_from_result(
        cls,
        result: Any,
        *,
        layer: str,
        source_tool: str | None = None,
        finding_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> EvidenceReference:
        """
        Convert an EvidenceStore result into EvidenceReference.

        Supports:

        - EvidenceReference
        - mappings
        - objects exposing common evidence attributes
        - string/path-like identifiers
        """

        if isinstance(
            result,
            EvidenceReference,
        ):
            return result

        if isinstance(
            result,
            Mapping,
        ):

            evidence_id = cls._mapping_value(
                result,
                "evidence_id",
                "id",
                "artifact_id",
            )

            if not evidence_id:

                evidence_id = cls._mapping_value(
                    result,
                    "path",
                    "file",
                )

            if not evidence_id:

                raise ValueError(
                    "EvidenceStore result does not contain "
                    "an evidence identifier."
                )

            return EvidenceReference(
                evidence_id=str(
                    evidence_id
                ),
                layer=layer,
                path=str(
                    cls._mapping_value(
                        result,
                        "path",
                        "file",
                    )
                    or ""
                ),
                sha256=cls._mapping_value(
                    result,
                    "sha256",
                    "hash",
                ),
                source_tool=(
                    source_tool
                    or cls._mapping_value(
                        result,
                        "source_tool",
                    )
                ),
                finding_id=(
                    finding_id
                    or cls._mapping_value(
                        result,
                        "finding_id",
                    )
                ),
                metadata=cls._merge_metadata(
                    metadata,
                    result.get(
                        "metadata",
                        {},
                    ),
                ),
            )

        evidence_id = cls._object_value(
            result,
            "evidence_id",
            "artifact_id",
            "id",
        )

        if not evidence_id:

            evidence_id = str(
                result
            ).strip()

        if not evidence_id:

            raise ValueError(
                "EvidenceStore returned an empty evidence identifier."
            )

        return EvidenceReference(
            evidence_id=str(
                evidence_id
            ),
            layer=layer,
            path=str(
                cls._object_value(
                    result,
                    "path",
                    "file",
                )
                or ""
            ),
            sha256=cls._object_value(
                result,
                "sha256",
                "hash",
            ),
            source_tool=source_tool,
            finding_id=finding_id,
            metadata=cls._merge_metadata(
                metadata
            ),
        )

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _require_finding(
        finding: Finding,
    ) -> None:
        """
        Validate a Finding input.
        """

        if not isinstance(
            finding,
            Finding,
        ):

            raise TypeError(
                "EvidenceManager expects a Finding object."
            )

    @staticmethod
    def _required_text(
        value: Any,
        field_name: str,
    ) -> str:
        """
        Require a non-empty textual value.
        """

        normalized = str(
            value
        ).strip()

        if not normalized:

            raise ValueError(
                f"{field_name} cannot be empty."
            )

        return normalized

    @staticmethod
    def _merge_metadata(
        primary: Mapping[str, Any] | None,
        secondary: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Merge evidence metadata without mutating caller-owned mappings.
        """

        result: dict[str, Any] = {}

        if primary is not None:

            result.update(
                deepcopy(
                    dict(
                        primary
                    )
                )
            )

        if secondary is not None:

            result.update(
                deepcopy(
                    dict(
                        secondary
                    )
                )
            )

        return result

    @staticmethod
    def _mapping_value(
        mapping: Mapping[str, Any],
        *names: str,
    ) -> Any:
        """
        Return the first non-empty mapping value.
        """

        for name in names:

            value = mapping.get(
                name
            )

            if (
                value is not None
                and str(value).strip()
            ):

                return value

        return None

    @staticmethod
    def _object_value(
        value: Any,
        *names: str,
    ) -> Any:
        """
        Return the first non-empty object attribute.
        """

        for name in names:

            candidate = getattr(
                value,
                name,
                None,
            )

            if (
                candidate is not None
                and str(candidate).strip()
            ):

                return candidate

        return None

    @staticmethod
    def _object_identifier(
        value: Any,
        field_name: str,
    ) -> str | None:
        """
        Extract an optional object identifier.
        """

        if isinstance(
            value,
            Mapping,
        ):

            identifier = value.get(
                field_name
            )

        else:

            identifier = getattr(
                value,
                field_name,
                None,
            )

        if identifier is None:
            return None

        normalized = str(
            identifier
        ).strip()

        return (
            normalized
            if normalized
            else None
        )

    @staticmethod
    def _parse_timestamp(
        value: Any,
    ) -> datetime:
        """
        Parse a serialized timestamp safely.
        """

        if isinstance(
            value,
            datetime,
        ):

            if value.tzinfo is None:

                return value.replace(
                    tzinfo=timezone.utc
                )

            return value

        if value:

            try:

                parsed = datetime.fromisoformat(
                    str(
                        value
                    ).replace(
                        "Z",
                        "+00:00",
                    )
                )

                if parsed.tzinfo is None:

                    parsed = parsed.replace(
                        tzinfo=timezone.utc
                    )

                return parsed

            except ValueError:
                pass

        return datetime.now(
            timezone.utc
        )


###############################################################################
# Convenience API
###############################################################################


_DEFAULT_MANAGER: EvidenceManager | None = None


def configure_default_manager(
    manager: EvidenceManager | None = None,
    *,
    root: str | Path | None = None,
) -> EvidenceManager:
    """
    Configure the process-wide convenience EvidenceManager.

    The manager is deliberately not created during module import because
    EvidenceStore requires an explicit assessment/run root.
    """

    global _DEFAULT_MANAGER

    if (
        manager is not None
        and root is not None
    ):

        raise ValueError(
            "Provide either manager or root, not both."
        )

    if manager is not None:

        if not isinstance(
            manager,
            EvidenceManager,
        ):

            raise TypeError(
                "manager must be an EvidenceManager."
            )

        _DEFAULT_MANAGER = manager

    elif root is not None:

        _DEFAULT_MANAGER = EvidenceManager(
            root=root
        )

    else:

        raise TypeError(
            "configure_default_manager requires either "
            "manager or root."
        )

    return _DEFAULT_MANAGER


def _get_default_manager() -> EvidenceManager:
    """
    Return the configured process-wide convenience manager.
    """

    if _DEFAULT_MANAGER is None:

        raise RuntimeError(
            "No default EvidenceManager is configured. "
            "Create EvidenceManager(root=<run-output-directory>) "
            "or call configure_default_manager(root=<run-output-directory>)."
        )

    return _DEFAULT_MANAGER


def store_raw_evidence(
    source_tool: str,
    data: Any,
    *,
    target: str | None = None,
    filename: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceReference:
    """
    Store raw evidence using the configured default EvidenceManager.
    """

    return _get_default_manager().store_raw(
        source_tool,
        data,
        target=target,
        filename=filename,
        metadata=metadata,
    )


def store_finding_evidence(
    finding: Finding,
    *,
    raw_evidence_id: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> EvidenceReference:
    """
    Store normalized finding evidence using the configured default manager.
    """

    return _get_default_manager().store_finding(
        finding,
        raw_evidence_id=raw_evidence_id,
        metadata=metadata,
    )


def store_correlated_evidence(
    groups: Iterable[Any],
    *,
    metadata: Mapping[str, Any] | None = None,
) -> list[EvidenceReference]:
    """
    Store correlated finding groups using the configured default manager.
    """

    return _get_default_manager().store_correlated(
        groups,
        metadata=metadata,
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "RAW_LAYER",
    "FINDINGS_LAYER",
    "CORRELATED_LAYER",
    "EvidenceReference",
    "EvidenceManager",
    "configure_default_manager",
    "store_raw_evidence",
    "store_finding_evidence",
    "store_correlated_evidence",
]
