"""
Reporting package for ScopeForgeX.

The reporting system follows a simple architecture:

Scanning Tools
        │
        ▼
   ReportData Model
        │
        ▼
 Report Generator(s)
        │
        ├── Markdown (current)
        ├── JSON (future)
        ├── HTML (future)
        └── PDF (future)
"""

from .models import (
    ReportData,
    StageResult,
    ScanStatistics,
    FindingSummary,
)

from .report_generator import ReportGenerator

__all__ = [
    "ReportData",
    "StageResult",
    "ScanStatistics",
    "FindingSummary",
    "ReportGenerator",
]
