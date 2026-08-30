"""
ScopeForgeX Finding Correlation
================================

Correlation layer for the universal ScopeForgeX Finding model.

Correlation groups related findings that describe the same assessment asset,
service, endpoint or security context.

The purpose of correlation is different from deduplication:

    Correlation
        Understands relationships between findings.

    Deduplication
        Removes repeated representations of the same finding.

Example
-------

Nmap
    -> 443 open

httpx
    -> HTTPS service

WhatWeb
    -> Apache

testssl.sh
    -> TLS 1.0 enabled

Nuclei
    -> related Apache issue

ScopeForgeX correlation understands that these observations belong to the
same asset/service context instead of treating them as unrelated tool output.

Design Principles
-----------------

- Correlation operates only on normalized findings.
- Correlation never performs network requests.
- Correlation never executes external tools.
- Correlation does not decide whether a finding is a vulnerability.
- Correlation does not replace deduplication.
- Original findings remain available.
- Source-tool information is preserved.
- Evidence remains attached to the originating findings.
- Correlation is deterministic.
- Weak relationships must not be presented as confirmed relationships.
- The correlation layer remains independent from reporting.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from scopeforgex.findings.model import Finding


###############################################################################
# Relationship Types
###############################################################################


ASSET_RELATIONSHIP = "asset"
SERVICE_RELATIONSHIP = "service"
ENDPOINT_RELATIONSHIP = "endpoint"
PARAMETER_RELATIONSHIP = "parameter"
REFERENCE_RELATIONSHIP = "reference"
TOOL_RELATIONSHIP = "tool"


###############################################################################
# Correlation Group
###############################################################################


@dataclass(slots=True)
class CorrelationGroup:
    """
    A deterministic group of related ScopeForgeX findings.

    A group represents a relationship between findings. It is not itself a
    vulnerability and does not replace any Finding object.
    """

    group_id: str

    relationship: str

    findings: list[Finding] = field(
        default_factory=list,
    )

    confidence: str = "Medium"

    key: str = ""

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    @property
    def finding_count(self) -> int:
        """Return the number of findings in the group."""

        return len(
            self.findings
        )

    @property
    def source_tools(self) -> list[str]:
        """Return unique source tools represented by the group."""

        tools: list[str] = []

        for finding in self.findings:
            value = self._value(
                finding,
                "source_tool",
            )

            if value and value not in tools:
                tools.append(
                    value
                )

        return tools

    def as_dict(self) -> dict[str, Any]:
        """Serialize the correlation group."""

        serialized_findings: list[Any] = []

        for finding in self.findings:
            if hasattr(
                finding,
                "as_dict",
            ):
                serialized_findings.append(
                    finding.as_dict()
                )
            else:
                serialized_findings.append(
                    finding
                )

        return {
            "group_id": self.group_id,
            "relationship": self.relationship,
            "confidence": self.confidence,
            "key": self.key,
            "finding_count": self.finding_count,
            "source_tools": self.source_tools,
            "findings": serialized_findings,
            "metadata": dict(
                self.metadata
            ),
        }

    @staticmethod
    def _value(
        finding: Finding,
        field_name: str,
    ) -> str:
        """Safely extract a normalized finding field."""

        value = getattr(
            finding,
            field_name,
            "",
        )

        if value is None:
            return ""

        return str(
            value
        ).strip()


###############################################################################
# Correlator
###############################################################################


class FindingCorrelator:
    """
    Correlate normalized ScopeForgeX findings.

    Correlation is intentionally conservative.

    Strong identifiers such as:

    - exact URL
    - host + port
    - normalized endpoint
    - explicit target

    are preferred over weaker textual similarities.

    The correlator never merges Finding objects. It creates relationship
    groups while preserving every original finding.
    """

    name = "finding_correlator"

    description = (
        "Correlate normalized ScopeForgeX findings by shared asset, service, "
        "endpoint and reference context."
    )

    ###########################################################################
    # Public API
    ###########################################################################

    def correlate(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate normalized findings.

        Returns:
            Deterministic correlation groups.

        Empty input returns an empty list.
        """

        normalized = self._normalize_input(
            findings
        )

        if not normalized:
            return []

        groups: list[CorrelationGroup] = []

        groups.extend(
            self._correlate_by_asset(
                normalized
            )
        )

        groups.extend(
            self._correlate_by_service(
                normalized
            )
        )

        groups.extend(
            self._correlate_by_endpoint(
                normalized
            )
        )

        return self._deduplicate_groups(
            groups
        )

    def correlate_by_asset(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate findings that belong to the same assessment asset.
        """

        normalized = self._normalize_input(
            findings
        )

        return self._correlate_by_asset(
            normalized
        )

    def correlate_by_service(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate findings that belong to the same host/service.
        """

        normalized = self._normalize_input(
            findings
        )

        return self._correlate_by_service(
            normalized
        )

    def correlate_by_endpoint(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """
        Correlate findings that belong to the same endpoint.
        """

        normalized = self._normalize_input(
            findings
        )

        return self._correlate_by_endpoint(
            normalized
        )

    ###########################################################################
    # Input Normalization
    ###########################################################################

    @staticmethod
    def _normalize_input(
        findings: Iterable[Finding],
    ) -> list[Finding]:
        """
        Normalize correlation input.

        Existing Finding objects are required because correlation operates
        after finding normalization.
        """

        if findings is None:
            return []

        if isinstance(
            findings,
            Finding,
        ):
            return [findings]

        result: list[Finding] = []

        try:
            iterator = iter(
                findings
            )
        except TypeError as exc:
            raise TypeError(
                "Correlation input must be an iterable of Finding objects."
            ) from exc

        for finding in iterator:

            if not isinstance(
                finding,
                Finding,
            ):
                raise TypeError(
                    "FindingCorrelator expects normalized Finding objects."
                )

            result.append(
                finding
            )

        return result

    ###########################################################################
    # Asset Correlation
    ###########################################################################

    def _correlate_by_asset(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Group findings sharing the same normalized asset identity.
        """

        buckets: dict[str, list[Finding]] = {}

        for finding in findings:

            key = self._asset_key(
                finding
            )

            if not key:
                continue

            buckets.setdefault(
                key,
                [],
            ).append(
                finding
            )

        return self._groups_from_buckets(
            buckets,
            relationship=ASSET_RELATIONSHIP,
            prefix="ASSET",
        )

    ###########################################################################
    # Service Correlation
    ###########################################################################

    def _correlate_by_service(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Group findings sharing a host and port/service context.
        """

        buckets: dict[str, list[Finding]] = {}

        for finding in findings:

            key = self._service_key(
                finding
            )

            if not key:
                continue

            buckets.setdefault(
                key,
                [],
            ).append(
                finding
            )

        return self._groups_from_buckets(
            buckets,
            relationship=SERVICE_RELATIONSHIP,
            prefix="SERVICE",
        )

    ###########################################################################
    # Endpoint Correlation
    ###########################################################################

    def _correlate_by_endpoint(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Group findings sharing the same normalized URL/endpoint.
        """

        buckets: dict[str, list[Finding]] = {}

        for finding in findings:

            key = self._endpoint_key(
                finding
            )

            if not key:
                continue

            buckets.setdefault(
                key,
                [],
            ).append(
                finding
            )

        return self._groups_from_buckets(
            buckets,
            relationship=ENDPOINT_RELATIONSHIP,
            prefix="ENDPOINT",
        )

    ###########################################################################
    # Key Construction
    ###########################################################################

    @classmethod
    def _asset_key(
        cls,
        finding: Finding,
    ) -> str:
        """
        Build an asset-level correlation key.

        Priority:

        1. host
        2. target
        3. URL hostname
        """

        host = cls._field(
            finding,
            "host",
        )

        if host:
            return (
                f"host:{cls._normalize_host(host)}"
            )

        target = cls._field(
            finding,
            "target",
        )

        if target:
            parsed = urlparse(
                target
            )

            if parsed.hostname:
                return (
                    f"host:{cls._normalize_host(parsed.hostname)}"
                )

            return (
                f"target:{target.lower()}"
            )

        url = cls._field(
            finding,
            "url",
        )

        if url:
            parsed = urlparse(
                url
            )

            if parsed.hostname:
                return (
                    f"host:{cls._normalize_host(parsed.hostname)}"
                )

        return ""

    @classmethod
    def _service_key(
        cls,
        finding: Finding,
    ) -> str:
        """
        Build a host/service correlation key.

        A port is required to establish a strong service relationship.
        """

        host = cls._field(
            finding,
            "host",
        )

        port = getattr(
            finding,
            "port",
            None,
        )

        if host and port is not None:
            return (
                f"service:"
                f"{cls._normalize_host(host)}:"
                f"{port}"
            )

        url = cls._field(
            finding,
            "url",
        )

        if not url:
            return ""

        parsed = urlparse(
            url
        )

        if not parsed.hostname:
            return ""

        normalized_host = cls._normalize_host(
            parsed.hostname
        )

        effective_port = parsed.port

        if effective_port is None:

            if parsed.scheme.lower() == "https":
                effective_port = 443

            elif parsed.scheme.lower() == "http":
                effective_port = 80

        if effective_port is None:
            return ""

        return (
            f"service:"
            f"{normalized_host}:"
            f"{effective_port}"
        )

    @classmethod
    def _endpoint_key(
        cls,
        finding: Finding,
    ) -> str:
        """
        Build an endpoint correlation key.

        URL path is normalized while preserving query-independent endpoint
        identity.
        """

        url = cls._field(
            finding,
            "url",
        )

        if not url:
            return ""

        parsed = urlparse(
            url
        )

        if not parsed.hostname:
            return ""

        scheme = parsed.scheme.lower()

        host = cls._normalize_host(
            parsed.hostname
        )

        path = (
            parsed.path
            or "/"
        ).rstrip(
            "/"
        )

        if not path:
            path = "/"

        return (
            f"endpoint:"
            f"{scheme}://"
            f"{host}"
            f"{path.lower()}"
        )

    ###########################################################################
    # Group Construction
    ###########################################################################

    @classmethod
    def _groups_from_buckets(
        cls,
        buckets: Mapping[str, list[Finding]],
        *,
        relationship: str,
        prefix: str,
    ) -> list[CorrelationGroup]:
        """
        Convert correlation buckets into structured groups.

        Groups containing fewer than two findings are not returned because a
        correlation relationship requires more than one observation.
        """

        groups: list[CorrelationGroup] = []

        for index, key in enumerate(
            sorted(
                buckets
            ),
            start=1,
        ):

            group_findings = buckets[
                key
            ]

            if len(
                group_findings
            ) < 2:
                continue

            confidence = cls._group_confidence(
                group_findings
            )

            groups.append(
                CorrelationGroup(
                    group_id=(
                        f"CF-{prefix}-{index:04d}"
                    ),
                    relationship=relationship,
                    findings=list(
                        group_findings
                    ),
                    confidence=confidence,
                    key=key,
                    metadata={
                        "source_tool_count": len(
                            cls._source_tools(
                                group_findings
                            )
                        ),
                        "finding_types": cls._finding_types(
                            group_findings
                        ),
                    },
                )
            )

        return groups

    ###########################################################################
    # Confidence
    ###########################################################################

    @classmethod
    def _group_confidence(
        cls,
        findings: list[Finding],
    ) -> str:
        """
        Determine relationship confidence.

        This describes confidence in the correlation, not vulnerability
        confirmation.

        Multiple independent source tools increase relationship confidence
        when they share a strong correlation key.
        """

        source_tools = cls._source_tools(
            findings
        )

        if len(
            source_tools
        ) >= 3:
            return "Confirmed"

        if len(
            source_tools
        ) >= 2:
            return "High"

        return "Medium"

    ###########################################################################
    # Group Deduplication
    ###########################################################################

    @staticmethod
    def _deduplicate_groups(
        groups: list[CorrelationGroup],
    ) -> list[CorrelationGroup]:
        """
        Remove duplicate relationship groups while preserving findings.
        """

        unique: dict[
            tuple[str, str, tuple[str, ...]],
            CorrelationGroup,
        ] = {}

        for group in groups:

            finding_ids: list[str] = []

            for finding in group.findings:

                finding_id = str(
                    getattr(
                        finding,
                        "id",
                        "",
                    )
                ).strip()

                if not finding_id:
                    finding_id = str(
                        id(
                            finding
                        )
                    )

                finding_ids.append(
                    finding_id
                )

            key = (
                group.relationship,
                group.key,
                tuple(
                    sorted(
                        finding_ids
                    )
                ),
            )

            if key not in unique:
                unique[key] = group

        return list(
            unique.values()
        )

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _field(
        finding: Finding,
        field_name: str,
    ) -> str:
        """
        Safely retrieve a finding string field.
        """

        value = getattr(
            finding,
            field_name,
            "",
        )

        if value is None:
            return ""

        return str(
            value
        ).strip()

    @staticmethod
    def _normalize_host(
        host: str,
    ) -> str:
        """
        Normalize a hostname or IP address.
        """

        normalized = host.strip().lower()

        if normalized.endswith(
            "."
        ):
            normalized = normalized[:-1]

        return normalized

    @classmethod
    def _source_tools(
        cls,
        findings: list[Finding],
    ) -> set[str]:
        """
        Return unique source tools.
        """

        tools: set[str] = set()

        for finding in findings:

            source = cls._field(
                finding,
                "source_tool",
            )

            if source:
                tools.add(
                    source.lower()
                )

        return tools

    @classmethod
    def _finding_types(
        cls,
        findings: list[Finding],
    ) -> list[str]:
        """
        Return unique finding categories/types in stable order.
        """

        values: set[str] = set()

        for finding in findings:

            value = cls._field(
                finding,
                "category",
            )

            if not value:
                value = cls._field(
                    finding,
                    "title",
                )

            if value:
                values.add(
                    value
                )

        return sorted(
            values
        )


###############################################################################
# Convenience API
###############################################################################


_DEFAULT_CORRELATOR = FindingCorrelator()


def correlate_findings(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """
    Correlate findings using the default ScopeForgeX correlator.
    """

    return _DEFAULT_CORRELATOR.correlate(
        findings
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "ASSET_RELATIONSHIP",
    "SERVICE_RELATIONSHIP",
    "ENDPOINT_RELATIONSHIP",
    "PARAMETER_RELATIONSHIP",
    "REFERENCE_RELATIONSHIP",
    "TOOL_RELATIONSHIP",
    "CorrelationGroup",
    "FindingCorrelator",
    "correlate_findings",
]
