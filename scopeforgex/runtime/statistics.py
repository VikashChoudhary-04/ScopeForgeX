"""
ScopeForgeX Runtime Statistics
==============================

Defines the immutable runtime statistics model used throughout the
ScopeForgeX execution engine.

Statistics are updated during workflow execution and become the
authoritative source for reporting. Report generators should consume this
model instead of recounting files or parsing artifacts.

Design Principles
-----------------
- Strong typing.
- Dataclass-based model.
- Incremental updates.
- Standard-library only.
- JSON serialization friendly.
- Independent of filesystem state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class WorkflowStatistics:
    """
    Stores execution statistics collected during a workflow.

    All counters are maintained incrementally while the workflow executes.
    """

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    subdomains_discovered: int = 0
    alive_hosts: int = 0
    validated_hosts: int = 0
    urls_discovered: int = 0
    endpoints_discovered: int = 0

    # ------------------------------------------------------------------
    # Vulnerability Assessment
    # ------------------------------------------------------------------

    nuclei_findings: int = 0
    findings_total: int = 0

    findings_info: int = 0
    findings_low: int = 0
    findings_medium: int = 0
    findings_high: int = 0
    findings_critical: int = 0

    # ------------------------------------------------------------------
    # Runtime
    # ------------------------------------------------------------------

    tools_executed: int = 0
    tools_failed: int = 0
    stages_completed: int = 0

    warnings: int = 0
    errors: int = 0

    artifacts_generated: int = 0

    # ------------------------------------------------------------------
    # Increment Helpers
    # ------------------------------------------------------------------

    def increment_subdomains(self, count: int = 1) -> None:
        self.subdomains_discovered += count

    def increment_alive_hosts(self, count: int = 1) -> None:
        self.alive_hosts += count

    def increment_validated_hosts(self, count: int = 1) -> None:
        self.validated_hosts += count

    def increment_urls(self, count: int = 1) -> None:
        self.urls_discovered += count

    def increment_endpoints(self, count: int = 1) -> None:
        self.endpoints_discovered += count

    def increment_nuclei_findings(self, count: int = 1) -> None:
        self.nuclei_findings += count

    def increment_findings(
        self,
        *,
        info: int = 0,
        low: int = 0,
        medium: int = 0,
        high: int = 0,
        critical: int = 0,
    ) -> None:
        self.findings_info += info
        self.findings_low += low
        self.findings_medium += medium
        self.findings_high += high
        self.findings_critical += critical

        self.findings_total += (
            info +
            low +
            medium +
            high +
            critical
        )

    def increment_tools_executed(self, count: int = 1) -> None:
        self.tools_executed += count

    def increment_tools_failed(self, count: int = 1) -> None:
        self.tools_failed += count

    def increment_stages_completed(self, count: int = 1) -> None:
        self.stages_completed += count

    def increment_warnings(self, count: int = 1) -> None:
        self.warnings += count

    def increment_errors(self, count: int = 1) -> None:
        self.errors += count

    def increment_artifacts(self, count: int = 1) -> None:
        self.artifacts_generated += count

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def merge(self, other: "WorkflowStatistics") -> None:
        """
        Merge another statistics object into this one.
        """

        for field_name in self.__dataclass_fields__:
            setattr(
                self,
                field_name,
                getattr(self, field_name) + getattr(other, field_name),
            )

    def reset(self) -> None:
        """
        Reset all counters to zero.
        """

        for field_name in self.__dataclass_fields__:
            setattr(self, field_name, 0)

    def as_dict(self) -> dict[str, int]:
        """
        Return a dictionary representation.
        """

        return asdict(self)


__all__ = [
    "WorkflowStatistics",
]
