"""
ScopeForgeX Native Analyzer Engine
===================================

Central orchestration layer for ScopeForgeX-native evidence analyzers.

The analyzer engine coordinates the native analysis capabilities defined by
the final ScopeForgeX project plan:

- HTTP security headers
- Cookie security
- CORS
- HTTP methods
- Sensitive information exposure
- API-specific attack-surface analysis

Architecture
------------

Collected Evidence
        |
        v
Native Analyzer Engine
        |
        +--> HTTP Security Headers Analyzer
        |
        +--> Cookie Security Analyzer
        |
        +--> CORS Analyzer
        |
        +--> HTTP Methods Analyzer
        |
        +--> Sensitive Information Analyzer
        |
        +--> API Analyzer
        |
        v
Structured Analyzer Findings
        |
        v
Finding Normalization
        |
        v
Correlation / Deduplication
        |
        v
Reporting

Design Principles
-----------------

- Native analyzers operate only on collected evidence.
- Native analyzers never perform network requests.
- Native analyzers never execute external tools.
- The engine does not construct tool commands.
- The engine does not own external tool execution.
- Analyzer failures do not discard collected evidence.
- Analyzer output remains structured.
- Detection is not automatically confirmation.
- Native analysis complements external security tools.
- Every analyzer has a defined assessment purpose and input/output boundary.

The engine intentionally remains independent from the reporting layer and
the external-tool execution layer.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from scopeforgex.analyzers.api import APIAnalyzer
from scopeforgex.analyzers.cookies import CookieSecurityAnalyzer
from scopeforgex.analyzers.cors import CORSSecurityAnalyzer
from scopeforgex.analyzers.http_headers import (
    HttpSecurityHeaderAnalyzer,
)
from scopeforgex.analyzers.http_methods import (
    HTTPMethodsAnalyzer,
)
from scopeforgex.analyzers.sensitive_information import (
    SensitiveInformationAnalyzer,
)


###############################################################################
# Analyzer Result
###############################################################################


@dataclass(slots=True)
class AnalyzerResult:
    """
    Result produced by one native analyzer.

    AnalyzerResult preserves both successful observations and analyzer
    failures without modifying the original collected evidence.
    """

    analyzer: str

    success: bool = True

    findings: list[Any] = field(
        default_factory=list,
    )

    errors: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def add_finding(
        self,
        finding: Any,
    ) -> None:
        """
        Add a structured analyzer finding.
        """

        if finding is None:
            return

        self.findings.append(
            finding
        )

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Add an analyzer error.
        """

        if not error:
            return

        self.success = False

        self.errors.append(
            str(error)
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the analyzer result.
        """

        serialized_findings: list[Any] = []

        for finding in self.findings:

            if hasattr(
                finding,
                "as_dict",
            ):

                serialized_findings.append(
                    finding.as_dict()
                )

            elif isinstance(
                finding,
                Mapping,
            ):

                serialized_findings.append(
                    dict(finding)
                )

            else:

                serialized_findings.append(
                    finding
                )

        return {
            "analyzer": self.analyzer,
            "success": self.success,
            "findings": serialized_findings,
            "errors": list(
                self.errors
            ),
            "metadata": dict(
                self.metadata
            ),
        }


###############################################################################
# Engine
###############################################################################


class NativeAnalyzerEngine:
    """
    Execute ScopeForgeX-native analyzers against collected evidence.

    The engine is deliberately evidence-driven.

    It accepts already-collected evidence and passes that evidence to the
    selected native analyzers. It does not retrieve additional information.

    Default analyzer order follows the native analyzer capabilities defined
    by the final ScopeForgeX plan.
    """

    name = "native_analyzer_engine"

    description = (
        "Run ScopeForgeX-native deterministic analyzers against collected "
        "assessment evidence."
    )

    def __init__(
        self,
        analyzers: list[Any] | None = None,
    ) -> None:
        """
        Initialize the native analyzer engine.

        Args:
            analyzers:
                Optional explicit analyzer instances.

                When omitted, the complete plan-defined native analyzer set
                is used.
        """

        if analyzers is None:

            analyzers = [
                HttpSecurityHeaderAnalyzer(),
                CookieSecurityAnalyzer(),
                CORSSecurityAnalyzer(),
                HTTPMethodsAnalyzer(),
                SensitiveInformationAnalyzer(),
                APIAnalyzer(),
            ]

        self.analyzers = list(
            analyzers
        )

    ###########################################################################
    # Analyzer Registration
    ###########################################################################

    def add_analyzer(
        self,
        analyzer: Any,
    ) -> None:
        """
        Add a native analyzer to the engine.

        The analyzer must expose:

            name
            analyze(evidence)

        Duplicate analyzer names are ignored.
        """

        if analyzer is None:
            return

        analyzer_name = self._analyzer_name(
            analyzer
        )

        if not analyzer_name:
            raise ValueError(
                "Analyzer must define a non-empty name."
            )

        existing = {
            self._analyzer_name(
                item
            )
            for item in self.analyzers
        }

        if analyzer_name in existing:
            return

        if not callable(
            getattr(
                analyzer,
                "analyze",
                None,
            )
        ):
            raise TypeError(
                f"Analyzer '{analyzer_name}' does not implement analyze()."
            )

        self.analyzers.append(
            analyzer
        )

    ###########################################################################
    # Analyzer Removal
    ###########################################################################

    def remove_analyzer(
        self,
        analyzer_name: str,
    ) -> None:
        """
        Remove an analyzer by name.

        Removing an analyzer does not alter the evidence or any other
        analyzer configuration.
        """

        normalized = str(
            analyzer_name
        ).strip().lower()

        self.analyzers = [
            analyzer
            for analyzer in self.analyzers
            if self._analyzer_name(
                analyzer
            ) != normalized
        ]

    ###########################################################################
    # Analysis
    ###########################################################################

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[Any]:
        """
        Run all configured native analyzers.

        Args:
            evidence:
                Already-collected assessment evidence.

        Returns:
            Combined structured findings produced by the configured
            analyzers.

        Analyzer failures are isolated. A failure in one analyzer does not
        prevent the remaining analyzers from processing the evidence.
        """

        if not isinstance(
            evidence,
            Mapping,
        ):
            raise TypeError(
                "Native analyzer evidence must be a mapping."
            )

        findings: list[Any] = []

        for analyzer in self.analyzers:

            result = self._run_analyzer(
                analyzer,
                evidence,
            )

            findings.extend(
                result.findings
            )

        return findings

    ###########################################################################
    # Detailed Analysis
    ###########################################################################

    def analyze_with_results(
        self,
        evidence: Mapping[str, Any],
    ) -> list[AnalyzerResult]:
        """
        Run all configured native analyzers and preserve per-analyzer results.

        This method is useful when the workflow needs to retain analyzer
        execution status and errors in addition to the produced findings.
        """

        if not isinstance(
            evidence,
            Mapping,
        ):
            raise TypeError(
                "Native analyzer evidence must be a mapping."
            )

        results: list[AnalyzerResult] = []

        for analyzer in self.analyzers:

            results.append(
                self._run_analyzer(
                    analyzer,
                    evidence,
                )
            )

        return results

    ###########################################################################
    # Single Analyzer
    ###########################################################################

    def analyze_one(
        self,
        analyzer_name: str,
        evidence: Mapping[str, Any],
    ) -> AnalyzerResult:
        """
        Run one configured native analyzer.

        Args:
            analyzer_name:
                Registered analyzer name.

            evidence:
                Already-collected assessment evidence.

        Returns:
            AnalyzerResult.

        Raises:
            ValueError:
                If the requested analyzer is not registered.
        """

        normalized = str(
            analyzer_name
        ).strip().lower()

        for analyzer in self.analyzers:

            if (
                self._analyzer_name(
                    analyzer
                )
                == normalized
            ):

                return self._run_analyzer(
                    analyzer,
                    evidence,
                )

        raise ValueError(
            f"Unknown native analyzer: {analyzer_name}"
        )

    ###########################################################################
    # Internal Execution
    ###########################################################################

    def _run_analyzer(
        self,
        analyzer: Any,
        evidence: Mapping[str, Any],
    ) -> AnalyzerResult:
        """
        Execute one analyzer while isolating analyzer failures.
        """

        name = self._analyzer_name(
            analyzer
        )

        result = AnalyzerResult(
            analyzer=name
        )

        analyze = getattr(
            analyzer,
            "analyze",
            None,
        )

        if not callable(
            analyze
        ):

            result.add_error(
                f"Analyzer '{name}' does not implement analyze()."
            )

            return result

        try:

            findings = analyze(
                evidence
            )

            if findings is None:
                return result

            if isinstance(
                findings,
                (list, tuple),
            ):

                for finding in findings:

                    result.add_finding(
                        finding
                    )

            else:

                result.add_finding(
                    findings
                )

        except Exception as exc:

            result.add_error(
                f"{name}: {exc}"
            )

        result.metadata[
            "finding_count"
        ] = len(
            result.findings
        )

        return result

    ###########################################################################
    # Metadata
    ###########################################################################

    def analyzer_names(
        self,
    ) -> list[str]:
        """
        Return registered native analyzer names in execution order.
        """

        return [
            self._analyzer_name(
                analyzer
            )
            for analyzer in self.analyzers
        ]

    def metadata(
        self,
    ) -> list[dict[str, Any]]:
        """
        Return metadata for all registered native analyzers.

        The engine does not require analyzers to implement a custom metadata
        interface. Name and description are taken from their public class
        attributes.
        """

        metadata: list[dict[str, Any]] = []

        for analyzer in self.analyzers:

            metadata.append(
                {
                    "name": self._analyzer_name(
                        analyzer
                    ),
                    "description": str(
                        getattr(
                            analyzer,
                            "description",
                            "",
                        )
                    ),
                }
            )

        return metadata

    ###########################################################################
    # Helpers
    ###########################################################################

    @staticmethod
    def _analyzer_name(
        analyzer: Any,
    ) -> str:
        """
        Return a normalized analyzer name.
        """

        return str(
            getattr(
                analyzer,
                "name",
                "",
            )
        ).strip().lower()


###############################################################################
# Public API
###############################################################################


__all__ = [
    "AnalyzerResult",
    "NativeAnalyzerEngine",
]
