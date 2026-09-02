"""
ScopeForgeX Vulnerability Intelligence
======================================

Public API for NVD, CPE, CVE and CISA KEV intelligence.
"""

from .engine import (
    VulnerabilityIntelligenceEngine,
)
from .kev import (
    KEVClient,
    KEV_URL,
)
from .models import (
    SoftwareObservation,
    VulnerabilityMatch,
)
from .nvd import (
    CPE_ENDPOINT,
    CVE_ENDPOINT,
    NVDClient,
    NVD_BASE_URL,
)

__all__ = [
    "CPE_ENDPOINT",
    "CVE_ENDPOINT",
    "KEVClient",
    "KEV_URL",
    "NVDClient",
    "NVD_BASE_URL",
    "SoftwareObservation",
    "VulnerabilityIntelligenceEngine",
    "VulnerabilityMatch",
]
