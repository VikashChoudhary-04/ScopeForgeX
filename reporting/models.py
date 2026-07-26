"""
reporting/models.py

Expanded reporting models for ScopeForgeX.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List


@dataclass
class ScanStatistics:
    subdomains_found: int = 0
    alive_hosts: int = 0
    final_hosts: int = 0
    urls_discovered: int = 0
    nuclei_findings: int = 0
    files_generated: int = 0


@dataclass
class StageResult:
    name: str
    status: str = "Completed"


@dataclass
class ReportData:
    target: str
    profile: str
    target_type: str

    start_time: datetime
    end_time: datetime

    duration_seconds: float = 0.0

    statistics: ScanStatistics = field(default_factory=ScanStatistics)

    stages: List[StageResult] = field(default_factory=list)

    generated_files: List[str] = field(default_factory=list)

    warnings: List[str] = field(default_factory=list)

    tool_results: Dict[str, str] = field(default_factory=dict)
