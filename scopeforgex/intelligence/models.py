"""
ScopeForgeX Vulnerability Intelligence Models
=============================================

Canonical data structures for the ScopeForgeX Vulnerability Intelligence
layer.

The intelligence layer distinguishes:

- observed software evidence;
- resolved CPE identity;
- NVD vulnerability applicability;
- CISA KEV prioritization;
- target-specific validation state.

A version-to-CVE match is a potential exposure. It is not proof of
exploitability, successful exploitation, or compromise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SoftwareObservation:
    """
    Observed product/version information from assessment evidence.
    """

    product: str

    version: str | None = None

    vendor: str | None = None

    cpe: str | None = None

    target: str | None = None

    host: str | None = None

    port: int | None = None

    url: str | None = None

    source_tool: str = ""

    detection_method: str = ""

    evidence: Any = None

    confidence: str = "Medium"

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass(frozen=True, slots=True)
class VulnerabilityMatch:
    """
    NVD/CISA intelligence associated with one observed software asset.
    """

    cve: str

    title: str

    description: str

    cpe: str

    product: str

    version: str | None

    target: str | None

    host: str | None

    port: int | None

    url: str | None

    severity: str = "Informational"

    cvss_score: float | None = None

    cvss_version: str | None = None

    cwes: tuple[str, ...] = ()

    references: tuple[str, ...] = ()

    kev: bool = False

    kev_date_added: str | None = None

    kev_due_date: str | None = None

    kev_ransomware_use: bool | None = None

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a JSON-compatible representation.
        """

        return {
            "cve": self.cve,
            "title": self.title,
            "description": self.description,
            "cpe": self.cpe,
            "product": self.product,
            "version": self.version,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "url": self.url,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "cwes": list(
                self.cwes
            ),
            "references": list(
                self.references
            ),
            "kev": self.kev,
            "kev_date_added": self.kev_date_added,
            "kev_due_date": self.kev_due_date,
            "kev_ransomware_use": self.kev_ransomware_use,
        }


__all__ = [
    "SoftwareObservation",
    "VulnerabilityMatch",
]
