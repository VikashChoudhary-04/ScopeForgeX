from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class StageResult:
    """
    Stores the result of one pipeline stage.
    Example:
        Stage 1 - Recon
        Stage 2 - Enumeration
        Stage 3 - Vulnerability Scan
    """

    name: str
    success: bool
    duration_seconds: float = 0.0
    summary: str = ""
    output_files: List[str] = field(default_factory=list)


@dataclass
class ScanStatistics:
    """
    Automatically calculated scan statistics.
    """

    subdomains_found: int = 0
    alive_hosts: int = 0
    final_hosts: int = 0

    urls_discovered: int = 0

    nuclei_findings: int = 0

    files_generated: int = 0


@dataclass
class FindingSummary:
    """
    Summary of findings by severity.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


@dataclass
class ReportData:
    """
    Single source of truth for the reporting engine.
    """

    # Target Information
    target: str
    profile: str
    target_type: str

    # Timing
    start_time: datetime
    end_time: datetime | None = None
    duration_seconds: float = 0.0

    # Results
    stages: List[StageResult] = field(default_factory=list)

    statistics: ScanStatistics = field(default_factory=ScanStatistics)

    findings: FindingSummary = field(default_factory=FindingSummary)

    warnings: List[str] = field(default_factory=list)

    errors: List[str] = field(default_factory=list)

    generated_files: List[str] = field(default_factory=list)
