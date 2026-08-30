"""
ScopeForgeX Finding Correlation
================================

Correlation layer for the universal ScopeForgeX Finding model.

Correlation groups related findings that describe the same assessment asset,
service, endpoint, parameter, or security context.

Correlation is intentionally separate from deduplication:

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
- Evidence remains attached to originating findings.
- Correlation is deterministic.
- Weak relationships are not presented as confirmed relationships.
- Correlation confidence is independent from finding confidence.
- The correlation layer remains independent from reporting.

v1.4.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from scopeforgex.models.finding import Finding


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
    Deterministic group of related ScopeForgeX findings.

    A correlation group represents a relationship between findings. It is not
    itself a vulnerability and does not replace any Finding object.
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
    def finding_count(
        self,
    ) -> int:
        """Return the number of findings in the group."""

        return len(
            self.findings
        )

    @property
    def source_tools(
        self,
    ) -> list[str]:
        """
        Return unique source tools represented by the group.

        Ordering follows first occurrence so serialization remains
        deterministic.
        """

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

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the correlation group into a JSON-compatible dictionary.
        """

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

    - exact host
    - host + port
    - normalized endpoint
    - endpoint + parameter
    - explicit target

    are preferred over weaker textual similarities.

    The correlator never merges Finding objects. It creates relationship
    groups while preserving every original finding.
    """

    name = "finding_correlator"

    description = (
        "Correlate normalized ScopeForgeX findings by shared asset, service, "
        "endpoint, parameter, and security context."
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

        groups.extend(
            self._correlate_by_parameter(
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
        """Correlate findings belonging to the same assessment asset."""

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
        """Correlate findings belonging to the same host/service."""

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
        """Correlate findings belonging to the same endpoint."""

        normalized = self._normalize_input(
            findings
        )

        return self._correlate_by_endpoint(
            normalized
        )

    def correlate_by_parameter(
        self,
        findings: Iterable[Finding],
    ) -> list[CorrelationGroup]:
        """Correlate findings sharing the same endpoint parameter."""

        normalized = self._normalize_input(
            findings
        )

        return self._correlate_by_parameter(
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

        Correlation operates after finding normalization, therefore all inputs
        must already be Finding instances.
        """

        if findings is None:
            return []

        if isinstance(
            findings,
            Finding,
        ):
            return [findings]

        try:
            iterator = iter(
                findings
            )

        except TypeError as exc:
            raise TypeError(
                "Correlation input must be an iterable of Finding objects."
            ) from exc

        result: list[Finding] = []

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
        """Group findings sharing the same normalized asset identity."""

        buckets: dict[
            str,
            list[Finding],
        ] = {}

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
        """Group findings sharing a host and port/service context."""

        buckets: dict[
            str,
            list[Finding],
        ] = {}

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
        Group findings sharing the same normalized URL endpoint.

        Query strings and fragments are excluded because endpoint correlation
        represents the resource path rather than a specific request instance.
        """

        buckets: dict[
            str,
            list[Finding],
        ] = {}

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
    # Parameter Correlation
    ###########################################################################

    def _correlate_by_parameter(
        self,
        findings: list[Finding],
    ) -> list[CorrelationGroup]:
        """
        Group findings sharing the same normalized endpoint parameter.

        A parameter relationship requires both:

        - a usable endpoint identity
        - a non-empty parameter

        This prevents identical parameter names on unrelated endpoints from
        being correlated together.
        """

        buckets: dict[
            str,
            list[Finding],
        ] = {}

        for finding in findings:

            key = self._parameter_key(
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
            relationship=PARAMETER_RELATIONSHIP,
            prefix="PARAMETER",
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
        2. target hostname
        3. URL hostname
        """

        host = cls._field(
            finding,
            "host",
        )

        if host:
            return (
                f"host:"
                f"{cls._normalize_host(host)}"
            )

        target = cls._field(
            finding,
            "target",
        )

        if target:

            parsed = cls._safe_urlparse(
                target
            )

            hostname = cls._safe_hostname(
                parsed
            )

            if hostname:
                return (
                    f"host:"
                    f"{cls._normalize_host(hostname)}"
                )

            normalized_target = target.lower()

            return (
                f"target:{normalized_target}"
            )

        url = cls._field(
            finding,
            "url",
        )

        if url:

            parsed = cls._safe_urlparse(
                url
            )

            hostname = cls._safe_hostname(
                parsed
            )

            if hostname:
                return (
                    f"host:"
                    f"{cls._normalize_host(hostname)}"
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

        parsed = cls._safe_urlparse(
            url
        )

        hostname = cls._safe_hostname(
            parsed
        )

        if not hostname:
            return ""

        normalized_host = cls._normalize_host(
            hostname
        )

        effective_port = cls._safe_port(
            parsed
        )

        if effective_port is None:

            scheme = (
                parsed.scheme.lower()
                if parsed is not None
                else ""
            )

            if scheme == "https":
                effective_port = 443

            elif scheme == "http":
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

        Query strings and fragments are intentionally excluded.

        Trailing slashes are normalized.
        """

        url = cls._field(
            finding,
            "url",
        )

        if not url:
            return ""

        parsed = cls._safe_urlparse(
            url
        )

        hostname = cls._safe_hostname(
            parsed
        )

        if not hostname:
            return ""

        scheme = (
            parsed.scheme.lower()
            if parsed is not None
            else ""
        )

        if not scheme:
            return ""

        host = cls._normalize_host(
            hostname
        )

        path = (
            parsed.path
            or "/"
        )

        path = path.rstrip(
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

    @classmethod
    def _parameter_key(
        cls,
        finding: Finding,
    ) -> str:
        """
        Build a parameter-level correlation key.

        Parameter identity is scoped to the normalized endpoint.
        """

        parameter = cls._field(
            finding,
            "parameter",
        )

        if not parameter:
            return ""

        endpoint = cls._endpoint_key(
            finding
        )

        if not endpoint:
            return ""

        return (
            f"parameter:"
            f"{endpoint}:"
            f"{parameter.lower()}"
        )

    ###########################################################################
    # Group Construction
    ###########################################################################

    @classmethod
    def _groups_from_buckets(
        cls,
        buckets: Mapping[
            str,
            list[Finding],
        ],
        *,
        relationship: str,
        prefix: str,
    ) -> list[CorrelationGroup]:
        """
        Convert correlation buckets into structured groups.

        Groups containing fewer than two findings are omitted because a
        correlation relationship requires multiple observations.
        """

        groups: list[CorrelationGroup] = []

        group_index = 1

        for key in sorted(
            buckets
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

            source_tools = cls._source_tools(
                group_findings
            )

            groups.append(
                CorrelationGroup(
                    group_id=(
                        f"CF-{prefix}-{group_index:04d}"
                    ),
                    relationship=relationship,
                    findings=list(
                        group_findings
                    ),
                    confidence=confidence,
                    key=key,
                    metadata={
                        "source_tool_count": len(
                            source_tools
                        ),
                        "source_tools": sorted(
                            source_tools
                        ),
                        "finding_types": cls._finding_types(
                            group_findings
                        ),
                    },
                )
            )

            group_index += 1

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
        Determine confidence in the correlation relationship.

        This does not represent vulnerability confirmation.

        Confidence:

            3+ source tools -> Confirmed
            2 source tools  -> High
            1 source tool   -> Medium
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
        Remove duplicate relationship groups.

        Findings are never removed.

        The same finding may legitimately appear in multiple groups:

            ASSET
                host:example.com

            SERVICE
                example.com:443

            ENDPOINT
                https://example.com/login
        """

        unique: dict[
            tuple[
                str,
                str,
                tuple[str, ...],
            ],
            CorrelationGroup,
        ] = {}

        for group in groups:

            finding_ids: list[str] = []

            for finding in group.findings:

                finding_id = str(
                    getattr(
                        finding,
                        "finding_id",
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
                unique[
                    key
                ] = group

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
        """Safely retrieve a finding string field."""

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

        - surrounding whitespace is removed
        - hostnames are case-insensitive
        - trailing DNS dots are removed
        """

        normalized = host.strip().lower()

        while normalized.endswith(
            "."
        ):
            normalized = normalized[:-1]

        return normalized

    @staticmethod
    def _safe_urlparse(
        value: str,
    ) -> Any | None:
        """
        Safely parse a URL.

        Malformed URLs are ignored rather than terminating correlation.
        """

        try:
            return urlparse(
                value
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_hostname(
        parsed: Any | None,
    ) -> str | None:
        """
        Safely retrieve a parsed URL hostname.

        ``ParseResult.hostname`` may raise ValueError for malformed bracketed
        host information.
        """

        if parsed is None:
            return None

        try:
            hostname = parsed.hostname

        except (
            TypeError,
            ValueError,
        ):
            return None

        if not hostname:
            return None

        return str(
            hostname
        )

    @staticmethod
    def _safe_port(
        parsed: Any | None,
    ) -> int | None:
        """
        Safely retrieve an explicitly supplied URL port.
        """

        if parsed is None:
            return None

        try:
            return parsed.port

        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _source_tools(
        cls,
        findings: list[Finding],
    ) -> set[str]:
        """Return unique normalized source tools."""

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
        """Return unique finding categories in stable order."""

        values: set[str] = set()

        for finding in findings:

            value = cls._field(
                finding,
                "category",
            )

            if value:
                values.add(
                    value
                )

        return sorted(
            values,
            key=str.lower,
        )


###############################################################################
# Module-Level Convenience API
###############################################################################


def correlate_findings(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Correlate normalized findings using the default correlator."""

    return FindingCorrelator().correlate(
        findings
    )


def correlate_by_asset(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Correlate normalized findings by assessment asset."""

    return FindingCorrelator().correlate_by_asset(
        findings
    )


def correlate_by_service(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Correlate normalized findings by service."""

    return FindingCorrelator().correlate_by_service(
        findings
    )


def correlate_by_endpoint(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Correlate normalized findings by endpoint."""

    return FindingCorrelator().correlate_by_endpoint(
        findings
    )


def correlate_by_parameter(
    findings: Iterable[Finding],
) -> list[CorrelationGroup]:
    """Correlate normalized findings by endpoint parameter."""

    return FindingCorrelator().correlate_by_parameter(
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
    "correlate_by_asset",
    "correlate_by_service",
    "correlate_by_endpoint",
    "correlate_by_parameter",
]
