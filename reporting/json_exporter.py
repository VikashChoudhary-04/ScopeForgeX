"""
ScopeForgeX JSON Report Exporter
================================

Machine-readable report exporter.

v0.6.1

Responsibilities:
    - Export ReportData to JSON
    - Serialize ExecutionResult objects
    - Preserve workflow metadata
    - Enable automation/dashboard integrations
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from reporting.models import ReportData


###############################################################################
# JSON Serialization Helpers
###############################################################################


def _json_safe(
    value: Any,
) -> Any:
    """
    Convert objects into JSON serializable structures.
    """

    if value is None:
        return None


    if isinstance(
        value,
        (str, int, float, bool),
    ):

        return value


    if isinstance(
        value,
        datetime,
    ):

        return value.isoformat()


    if isinstance(
        value,
        list,
    ):

        return [
            _json_safe(item)
            for item in value
        ]


    if isinstance(
        value,
        tuple,
    ):

        return [
            _json_safe(item)
            for item in value
        ]


    if isinstance(
        value,
        dict,
    ):

        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }


    if is_dataclass(
        value,
    ):

        return {
            key: _json_safe(item)
            for key, item in asdict(value).items()
        }


    if hasattr(
        value,
        "as_dict",
    ):

        return _json_safe(
            value.as_dict()
        )


    if hasattr(
        value,
        "__dict__",
    ):

        return {
            key: _json_safe(item)
            for key, item in value.__dict__.items()
        }


    return str(value)



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

        payload = self.report.as_dict()

        return _json_safe(
            payload
        )



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
