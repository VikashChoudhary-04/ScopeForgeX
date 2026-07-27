"""
ScopeForgeX JSON Report Exporter
================================

Machine-readable report exporter.

v0.6.0

Responsibilities:
    - Export ReportData to JSON
    - Preserve findings
    - Preserve workflow metadata
    - Enable automation/dashboard integrations
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reporting.models import ReportData


###############################################################################
# JSON Exporter
###############################################################################


class JSONReportExporter:
    """
    Generates JSON reports from ReportData.
    """

    def __init__(
        self,
        report: ReportData,
    ) -> None:

        self.report = report


    ###########################################################################
    # Serialization
    ###########################################################################

    def build_payload(
        self,
    ) -> dict[str, Any]:
        """
        Build JSON-compatible report payload.
        """

        return self.report.as_dict()


    ###########################################################################
    # File Output
    ###########################################################################

    def export(
        self,
        output_file: str,
    ) -> None:
        """
        Write JSON report.
        """

        path = Path(
            output_file
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        path.write_text(
            json.dumps(
                self.build_payload(),
                indent=4,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )


###############################################################################
# Convenience Function
###############################################################################


def export_json_report(
    report: ReportData,
    output_file: str,
) -> None:
    """
    Export ReportData as JSON.
    """

    JSONReportExporter(
        report
    ).export(
        output_file
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "JSONReportExporter",
    "export_json_report",
]
