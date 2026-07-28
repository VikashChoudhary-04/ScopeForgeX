"""
ScopeForgeX Findings Engine
===========================

Vulnerability finding normalization layer.

v1.0.0

Responsibilities:
    - Parse scanner outputs
    - Normalize findings
    - Generate finding IDs
    - Attach evidence
    - Prepare data for reporting
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from reporting.models import (
    Finding,
    FindingEvidence,
)


###############################################################################
# Helpers
###############################################################################


def generate_finding_id(
    title: str,
    target: str,
) -> str:
    """
    Generate stable finding identifier.
    """

    value = (
        f"{title}:{target}"
    ).encode(
        "utf-8"
    )

    return (
        "F-"
        +
        hashlib.sha1(
            value
        ).hexdigest()[:8].upper()
    )



def normalize_severity(
    severity: str,
) -> str:
    """
    Normalize severity names.
    """

    severity = (
        severity
        .strip()
        .lower()
    )

    mapping = {

        "critical": "Critical",

        "high": "High",

        "medium": "Medium",

        "moderate": "Medium",

        "low": "Low",

        "info": "Informational",

        "informational":
            "Informational",

    }

    return mapping.get(
        severity,
        "Informational",
    )



###############################################################################
# Finding Collector
###############################################################################


class FindingCollector:
    """
    Collects findings from security tools.
    """

    def __init__(
        self,
    ) -> None:

        self.findings: list[Finding] = []


    ###########################################################################
    # Generic Finding
    ###########################################################################

    def add(
        self,
        title: str,
        severity: str,
        target: str,
        source: str,
        description: str = "",
        impact: str = "",
        remediation: str = "",
        evidence: FindingEvidence | None = None,
        cvss: float | None = None,
    ) -> Finding:
        """
        Add normalized finding.
        """

        finding = Finding(

            finding_id=
                generate_finding_id(
                    title,
                    target,
                ),

            title=title,

            severity=
                normalize_severity(
                    severity
                ),

            target=target,

            source=source,

            description=description,

            impact=impact,

            remediation=remediation,

            evidence=
                evidence
                or FindingEvidence(),

            cvss=cvss,
        )


        self.findings.append(
            finding
        )

        return finding



    ###########################################################################
    # Nuclei Parser
    ###########################################################################

    def parse_nuclei_file(
        self,
        path: str,
    ) -> list[Finding]:
        """
        Parse nuclei text output.

        Supports basic nuclei output:
        
        [severity] template target
        """

        file = Path(
            path
        )

        if not file.exists():

            return []


        parsed = []


        with file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as handle:


            for line in handle:

                line = (
                    line.strip()
                )


                if not line:

                    continue


                severity = (
                    "Informational"
                )


                lower = (
                    line.lower()
                )


                for level in (
                    "critical",
                    "high",
                    "medium",
                    "low",
                ):

                    if level in lower:

                        severity = level

                        break



                finding = self.add(

                    title=
                        "Nuclei Detection",

                    severity=
                        severity,

                    target=
                        "Unknown",

                    source=
                        "nuclei",

                    description=
                        line,

                    evidence=
                        FindingEvidence(
                            description=line
                        ),
                )


                parsed.append(
                    finding
                )


        return parsed



    ###########################################################################
    # Import Existing Tool Results
    ###########################################################################

    def from_execution_results(
        self,
        results: list,
    ) -> list[Finding]:
        """
        Convert tool execution results into findings.
        """

        for result in results:

            tool = getattr(
                result,
                "tool",
                "unknown",
            )


            for item in getattr(
                result,
                "findings",
                [],
            ):

                if isinstance(
                    item,
                    dict,
                ):

                    self.add(

                        title=item.get(
                            "title",
                            "Unnamed Finding",
                        ),

                        severity=item.get(
                            "severity",
                            "Informational",
                        ),

                        target=item.get(
                            "target",
                            "Unknown",
                        ),

                        source=tool,

                        description=item.get(
                            "description",
                            "",
                        ),

                        remediation=item.get(
                            "remediation",
                            "",
                        ),
                    )


        return self.findings



    ###########################################################################
    # Export
    ###########################################################################

    def all(
        self,
    ) -> list[Finding]:

        return self.findings



###############################################################################
# Public API
###############################################################################


__all__ = [

    "FindingCollector",

    "generate_finding_id",

    "normalize_severity",

]
