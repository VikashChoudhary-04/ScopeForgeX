"""
ScopeForgeX Analysis
====================

Finding-analysis pipeline and processing interfaces.

The analysis package provides the orchestration layer between normalized
observations and final ScopeForgeX findings.

Public components
-----------------

- AnalysisPipeline
- AnalysisResult
- NormalizerProtocol
- ConfidenceProtocol
- RiskProtocol
- DeduplicatorProtocol
- CorrelatorProtocol
- analyze

The canonical Finding model remains defined in ``reporting.models``.
"""

from .pipeline import (
    AnalysisPipeline,
    AnalysisResult,
    ConfidenceProtocol,
    CorrelatorProtocol,
    DeduplicatorProtocol,
    NormalizerProtocol,
    RiskProtocol,
    analyze,
)


__all__ = [
    "AnalysisPipeline",
    "AnalysisResult",
    "NormalizerProtocol",
    "ConfidenceProtocol",
    "RiskProtocol",
    "DeduplicatorProtocol",
    "CorrelatorProtocol",
    "analyze",
]
