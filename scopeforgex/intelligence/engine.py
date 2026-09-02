"""
ScopeForgeX Vulnerability Intelligence & Correlation Engine
===========================================================

Converts observed software identity into conservative vulnerability
intelligence.

Pipeline
--------

Observed Product / Version
        |
        +--> Explicit CPE
        |
        +--> Conservative NVD CPE Resolution
                    |
                    v
             Version-specific CPE
                    |
                    v
             NVD CVE Applicability
                    |
             +------+------+
             |             |
             v             v
           CVSS          CWE
             |
             v
           CISA KEV
             |
             v
   Potential Vulnerability Finding
             |
             v
      Target-specific validation

The engine never labels a version-intelligence match as confirmed.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from scopeforgex.collectors.base import (
    CollectorObservation,
)

from .kev import KEVClient
from .models import SoftwareObservation
from .nvd import NVDClient


_CPE_RE = re.compile(
    r"^cpe:2\.3:[^:]+:[^:]+:[^:]+:.*$",
    re.IGNORECASE,
)

_CVE_RE = re.compile(
    r"\bCVE-[A-Z0-9]+-\d{1,}\b",
    re.IGNORECASE,
)


class VulnerabilityIntelligenceEngine:
    """
    Correlate observed software with NVD applicability and CISA KEV.
    """

    name = (
        "vulnerability_intelligence"
    )

    SOFTWARE_TYPES = frozenset(
        {
            "SERVICE",
            "SERVICE_VERSION",
            "TECHNOLOGY",
            "FRAMEWORK",
            "CMS",
            "SERVER",
            "LIBRARY",
        }
    )

    def __init__(
        self,
        *,
        nvd_client: NVDClient | None = None,
        kev_client: KEVClient | None = None,
        allow_network: bool = False,
        cache_dir: str = (
            ".cache/scopeforgex"
        ),
    ) -> None:
        self.allow_network = bool(
            allow_network
        )

        self.nvd = (
            nvd_client
            if nvd_client is not None
            else NVDClient(
                cache_dir=(
                    f"{cache_dir}/nvd"
                ),
                allow_network=(
                    self.allow_network
                ),
            )
        )

        self.kev = (
            kev_client
            if kev_client is not None
            else KEVClient(
                cache_file=(
                    f"{cache_dir}/kev/"
                    "known_exploited_vulnerabilities.json"
                ),
                allow_network=(
                    self.allow_network
                ),
            )
        )

    ###########################################################################
    # Public API
    ###########################################################################

    def analyze(
        self,
        observations: Iterable[Any],
    ) -> list[CollectorObservation]:
        """
        Analyze software observations and return vulnerability-intelligence
        observations.

        The method only considers observations containing software identity
        and an exact version or explicit CPE.
        """

        software = self.extract_software(
            observations
        )

        results: list[
            CollectorObservation
        ] = []

        seen: set[
            tuple[
                str,
                str,
                str | None,
                int | None,
                str | None,
            ]
        ] = set()

        for item in software:
            cpe = (
                item.cpe
                or self._resolve_cpe(
                    item
                )
            )

            if not cpe:
                continue

            query_cpe = (
                self._materialize_version(
                    cpe,
                    item.version,
                )
            )

            cve_records = (
                self.nvd.cves_for_cpe(
                    query_cpe
                )
            )

            for record in cve_records:
                vulnerability = (
                    self._normalize_cve(
                        record
                    )
                )

                if vulnerability is None:
                    continue

                key = (
                    vulnerability["cve"],
                    query_cpe,
                    item.host,
                    item.port,
                    item.url,
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                kev = self.kev.find(
                    vulnerability["cve"]
                )

                results.append(
                    self._to_observation(
                        software=item,
                        cpe=query_cpe,
                        vulnerability=vulnerability,
                        kev=kev,
                    )
                )

        return results

    def extract_software(
        self,
        observations: Iterable[Any],
    ) -> list[SoftwareObservation]:
        """
        Extract software identities from collector observations.
        """

        result: list[
            SoftwareObservation
        ] = []

        seen: set[
            tuple[
                str,
                str | None,
                str | None,
                int | None,
                str | None,
            ]
        ] = set()

        for observation in observations:
            data = self._mapping(
                observation
            )

            if not data:
                continue

            metadata = data.get(
                "metadata",
                {},
            )

            if not isinstance(
                metadata,
                Mapping,
            ):
                metadata = {}

            evidence = data.get(
                "evidence"
            )

            if not isinstance(
                evidence,
                Mapping,
            ):
                evidence = {}

            observation_type = str(
                data.get(
                    "observation_type",
                    "",
                )
            ).strip().upper()

            if (
                observation_type
                not in self.SOFTWARE_TYPES
            ):
                product_present = any(
                    self._text(
                        metadata.get(
                            key
                        )
                    )
                    or self._text(
                        evidence.get(
                            key
                        )
                    )
                    for key in (
                        "product",
                        "technology",
                    )
                )

                if not product_present:
                    continue

            product = (
                self._first_text(
                    metadata.get(
                        "product"
                    ),
                    metadata.get(
                        "technology"
                    ),
                    evidence.get(
                        "product"
                    ),
                    evidence.get(
                        "technology"
                    ),
                )
            )

            version = (
                self._first_text(
                    metadata.get(
                        "version"
                    ),
                    evidence.get(
                        "version"
                    ),
                )
                or None
            )

            cpe = self._first_cpe(
                metadata.get(
                    "cpe"
                ),
                evidence.get(
                    "cpe"
                ),
            )

            if (
                not product
                and data.get(
                    "value"
                )
            ):
                product, inferred_version = (
                    self._split_product_version(
                        str(
                            data["value"]
                        )
                    )
                )

                if not version:
                    version = (
                        inferred_version
                    )

            if not product:
                continue

            item = SoftwareObservation(
                product=product,
                version=version,
                vendor=(
                    self._first_text(
                        metadata.get(
                            "vendor"
                        ),
                        evidence.get(
                            "vendor"
                        ),
                    )
                    or None
                ),
                cpe=cpe,
                target=(
                    self._first_text(
                        data.get(
                            "target"
                        )
                    )
                    or None
                ),
                host=(
                    self._first_text(
                        data.get(
                            "host"
                        ),
                        data.get(
                            "target"
                        ),
                    )
                    or None
                ),
                port=self._port(
                    data.get(
                        "port"
                    )
                ),
                url=(
                    self._first_text(
                        data.get(
                            "url"
                        )
                    )
                    or None
                ),
                source_tool=(
                    self._first_text(
                        data.get(
                            "source_tool"
                        )
                    )
                ),
                detection_method=(
                    self._first_text(
                        data.get(
                            "detection_method"
                        )
                    )
                ),
                evidence=data.get(
                    "evidence"
                ),
                confidence=(
                    self._first_text(
                        data.get(
                            "confidence"
                        )
                    )
                    or "Medium"
                ),
                metadata=dict(
                    metadata
                ),
            )

            key = (
                item.product.lower(),
                (
                    item.version.lower()
                    if item.version
                    else None
                ),
                (
                    item.host.lower()
                    if item.host
                    else None
                ),
                item.port,
                item.url,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                item
            )

        return result

    ###########################################################################
    # CPE Resolution
    ###########################################################################

    def _resolve_cpe(
        self,
        software: SoftwareObservation,
    ) -> str | None:
        """
        Resolve a product/version to an unambiguous NVD CPE.
        """

        if not software.version:
            return None

        resolved, _candidates = (
            self.nvd.resolve_cpe(
                product=software.product,
                version=software.version,
                vendor=software.vendor,
            )
        )

        if resolved:
            return resolved

        # Never guess between ambiguous CPE identities.
        return None

    @staticmethod
    def _materialize_version(
        cpe: str,
        version: str | None,
    ) -> str:
        """Materialize an observed version into canonical CPE 2.3 form."""

        text = str(
            cpe or ""
        ).strip()

        if not text:
            return ""

        parts = text.split(
            ":"
        )

        if len(parts) < 6:
            return text

        # Canonical CPE 2.3 has 14 colon-separated components:
        # cpe:2.3:part:vendor:product:version:update:edition:language:
        # sw_edition:target_sw:target_hw:other
        while len(parts) < 14:
            parts.append(
                "*"
            )

        if len(parts) > 14:
            return text

        version_value = str(
            version or ""
        ).strip()

        if version_value:
            parts[5] = (
                version_value.replace(
                    " ",
                    "_",
                )
            )

        return ":".join(
            parts
        )

    ###########################################################################
    # CVE Normalization
    ###########################################################################

    @staticmethod
    def _normalize_cve(
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """
        Normalize one NVD CVE API record.
        """

        cve = record.get(
            "cve"
        )

        if not isinstance(
            cve,
            Mapping,
        ):
            return None

        identifier = str(
            cve.get(
                "id",
                "",
            )
        ).strip().upper()

        if not _CVE_RE.fullmatch(
            identifier
        ):
            return None

        description = ""

        descriptions = cve.get(
            "descriptions",
            [],
        )

        if isinstance(
            descriptions,
            list,
        ):
            for item in descriptions:
                if not isinstance(
                    item,
                    Mapping,
                ):
                    continue

                if (
                    str(
                        item.get(
                            "lang",
                            "",
                        )
                    ).lower()
                    == "en"
                ):
                    description = str(
                        item.get(
                            "value",
                            "",
                        )
                    ).strip()
                    break

        cwes: list[str] = []

        weaknesses = cve.get(
            "weaknesses",
            [],
        )

        if isinstance(
            weaknesses,
            list,
        ):
            for weakness in weaknesses:
                if not isinstance(
                    weakness,
                    Mapping,
                ):
                    continue

                descriptions = (
                    weakness.get(
                        "description",
                        [],
                    )
                )

                if not isinstance(
                    descriptions,
                    list,
                ):
                    continue

                for item in descriptions:
                    if not isinstance(
                        item,
                        Mapping,
                    ):
                        continue

                    value = str(
                        item.get(
                            "value",
                            "",
                        )
                    ).strip().upper()

                    if value.startswith(
                        "CWE-"
                    ):
                        cwes.append(
                            value
                        )

        references: list[str] = []

        raw_references = cve.get(
            "references",
            [],
        )

        if isinstance(
            raw_references,
            list,
        ):
            for item in raw_references:
                if not isinstance(
                    item,
                    Mapping,
                ):
                    continue

                value = str(
                    item.get(
                        "url",
                        "",
                    )
                ).strip()

                if value:
                    references.append(
                        value
                    )

        score = None

        cvss_version = None

        severity = "Informational"

        metrics = cve.get(
            "metrics",
            {},
        )

        if isinstance(
            metrics,
            Mapping,
        ):
            for metric_key in (
                "cvssMetricV40",
                "cvssMetricV31",
                "cvssMetricV30",
                "cvssMetricV2",
            ):
                metric_values = (
                    metrics.get(
                        metric_key
                    )
                )

                if not isinstance(
                    metric_values,
                    list,
                ):
                    continue

                for metric in metric_values:
                    if not isinstance(
                        metric,
                        Mapping,
                    ):
                        continue

                    cvss_data = (
                        metric.get(
                            "cvssData",
                            {},
                        )
                    )

                    if not isinstance(
                        cvss_data,
                        Mapping,
                    ):
                        continue

                    raw_score = (
                        cvss_data.get(
                            "baseScore"
                        )
                    )

                    try:
                        score = float(
                            raw_score
                        )
                    except (
                        TypeError,
                        ValueError,
                    ):
                        score = None

                    cvss_version = str(
                        cvss_data.get(
                            "version",
                            "",
                        )
                    ).strip() or None

                    raw_severity = (
                        cvss_data.get(
                            "baseSeverity"
                        )
                        or metric.get(
                            "baseSeverity"
                        )
                    )

                    if raw_severity:
                        severity = str(
                            raw_severity
                        ).strip().title()

                    elif score is not None:
                        severity = (
                            VulnerabilityIntelligenceEngine
                            ._severity_from_score(
                                score
                            )
                        )

                    if (
                        score is not None
                        or raw_severity
                    ):
                        break

                if (
                    score is not None
                    or cvss_version
                ):
                    break

        title = (
            description.split(
                ".",
                1,
            )[0].strip()
            if description
            else identifier
        )

        if not title:
            title = identifier

        return {
            "cve": identifier,
            "title": title,
            "description": description,
            "severity": severity,
            "cvss_score": score,
            "cvss_version": cvss_version,
            "cwes": tuple(
                dict.fromkeys(
                    cwes
                )
            ),
            "references": tuple(
                dict.fromkeys(
                    references
                )
            ),
        }

    @staticmethod
    def _severity_from_score(
        score: float,
    ) -> str:
        """
        Map a CVSS base score to the conventional severity bands.
        """

        if score >= 9.0:
            return "Critical"

        if score >= 7.0:
            return "High"

        if score >= 4.0:
            return "Medium"

        if score > 0.0:
            return "Low"

        return "Informational"

    ###########################################################################
    # Observation Construction
    ###########################################################################

    @staticmethod
    def _to_observation(
        *,
        software: SoftwareObservation,
        cpe: str,
        vulnerability: Mapping[str, Any],
        kev: Mapping[str, Any] | None,
    ) -> CollectorObservation:
        """
        Convert intelligence into one canonical CollectorObservation.
        """

        cve = str(
            vulnerability[
                "cve"
            ]
        )

        kev_present = (
            kev is not None
        )

        cwes = list(
            vulnerability.get(
                "cwes",
                (),
            )
        )

        references = list(
            vulnerability.get(
                "references",
                (),
            )
        )

        description = str(
            vulnerability.get(
                "description",
                "",
            )
        ).strip()

        metadata: dict[str, Any] = {
            "intelligence_source": "NVD",
            "intelligence_type": (
                "cpe_applicability_match"
            ),
            "cpe": cpe,
            "product": software.product,
            "version": software.version,
            "source_tool": (
                software.source_tool
            ),
            "source_detection_method": (
                software.detection_method
            ),
            "cvss_score": (
                vulnerability.get(
                    "cvss_score"
                )
            ),
            "cvss_version": (
                vulnerability.get(
                    "cvss_version"
                )
            ),
            "cwes": cwes,
            "kev": kev_present,
            "validation_status": (
                "Pending"
            ),
            "version_based_match": True,
            "target_specific_validation": (
                False
            ),
        }

        if (
            kev_present
            and isinstance(
                kev,
                Mapping,
            )
        ):
            ransomware = str(
                kev.get(
                    "knownRansomwareCampaignUse",
                    "",
                )
            ).strip().lower()

            metadata.update(
                {
                    "kev_date_added": (
                        kev.get(
                            "dateAdded"
                        )
                    ),
                    "kev_due_date": (
                        kev.get(
                            "dueDate"
                        )
                    ),
                    "kev_ransomware_use": (
                        ransomware == "known"
                    ),
                    "kev_vendor_project": (
                        kev.get(
                            "vendorProject"
                        )
                    ),
                    "kev_product": (
                        kev.get(
                            "product"
                        )
                    ),
                }
            )

        return CollectorObservation(
            observation_type=(
                "VULNERABILITY_INTELLIGENCE"
            ),
            value=cve,
            title=(
                f"{cve}: "
                f"{vulnerability.get('title') or 'Potential Vulnerability'}"
            ),
            description=(
                "NVD CPE applicability indicates that the observed "
                "software/version may be affected. This is a version-based "
                "potential vulnerability, not confirmation of exploitability "
                "or compromise. Target-specific validation is required "
                "before treating it as confirmed."
                + (
                    " CISA currently lists this CVE in the Known Exploited "
                    "Vulnerabilities catalog."
                    if kev_present
                    else ""
                )
            ),
            impact=(
                description
                or (
                    "Potential impact is defined by the referenced "
                    "NVD vulnerability record."
                )
            ),
            remediation=(
                "Verify the exact installed product and version, review "
                "the vendor advisory, apply the vendor-supported fix or "
                "mitigation, and perform target-specific validation."
            ),
            severity=str(
                vulnerability.get(
                    "severity",
                    "Informational",
                )
            ),
            confidence="Medium",
            status="Pending",
            target=software.target,
            host=software.host,
            port=software.port,
            url=software.url,
            evidence={
                "observed_software": {
                    "product": software.product,
                    "version": software.version,
                    "cpe": cpe,
                },
                "original_evidence": (
                    software.evidence
                ),
            },
            source_tool="NVD",
            detection_method=(
                "NVD CPE applicability correlation"
            ),
            cwe=(
                cwes[0]
                if cwes
                else None
            ),
            cve=cve,
            references=references,
            metadata=metadata,
        )

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _mapping(
        value: Any,
    ) -> dict[str, Any]:
        """
        Safely convert a collector/analyzer object into a mapping.
        """

        if isinstance(
            value,
            Mapping,
        ):
            return dict(
                value
            )

        serializer = getattr(
            value,
            "as_dict",
            None,
        )

        if callable(
            serializer
        ):
            try:
                data = serializer()
            except Exception:
                return {}

            if isinstance(
                data,
                Mapping,
            ):
                return dict(
                    data
                )

        return {}

    @staticmethod
    def _text(
        value: Any,
    ) -> str:
        if value is None:
            return ""

        return str(
            value
        ).strip()

    @staticmethod
    def _first_text(
        *values: Any,
    ) -> str:
        for value in values:
            text = (
                VulnerabilityIntelligenceEngine
                ._text(
                    value
                )
            )

            if text:
                return text

        return ""

    @staticmethod
    def _first_cpe(
        *values: Any,
    ) -> str | None:
        for value in values:
            text = (
                VulnerabilityIntelligenceEngine
                ._text(
                    value
                )
            )

            if _CPE_RE.match(
                text
            ):
                return text

        return None

    @staticmethod
    def _split_product_version(
        value: str,
    ) -> tuple[str, str | None]:
        """
        Split a simple `Product 1.2.3` representation.
        """

        text = str(
            value
        ).strip()

        match = re.match(
            r"^(.*?)(?:\s+v?([0-9][A-Za-z0-9._+-]*))$",
            text,
        )

        if not match:
            return (
                text,
                None,
            )

        product = (
            match.group(
                1
            ).strip()
        )

        version = (
            match.group(
                2
            ).strip()
        )

        return (
            product,
            version,
        )

    @staticmethod
    def _port(
        value: Any,
    ) -> int | None:
        try:
            port = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

        if 1 <= port <= 65535:
            return port

        return None


__all__ = [
    "VulnerabilityIntelligenceEngine",
]
