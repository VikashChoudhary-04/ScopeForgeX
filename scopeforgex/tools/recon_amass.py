"""
ScopeForgeX — Amass Reconnaissance Adapter
==========================================

Amass integration for broad attack-surface discovery.

Primary capabilities
--------------------
- Subdomain discovery
- DNS asset discovery
- Host discovery
- Infrastructure relationship discovery

Output
------
Raw Amass output is preserved by the execution layer.

The adapter is responsible for:

- Tool metadata
- Supported options
- Command construction
- Standard execution
- Normalized tool identity

Finding normalization belongs to the collector layer.
"""

from __future__ import annotations

from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runtime.enums import AssessmentPhase


class AmassTool(ToolBase):
    """
    Amass reconnaissance adapter.

    Amass is the primary broad attack-surface discovery tool in the
    ScopeForgeX reconnaissance phase.
    """

    # ========================================================================
    # Identity
    # ========================================================================

    name = "amass"

    display_name = "Amass"

    description = (
        "Broad attack-surface and infrastructure discovery"
    )

    # ========================================================================
    # Assessment Contract
    # ========================================================================

    phase = AssessmentPhase.RECONNAISSANCE

    input_type = "domain"

    output_type = "discovery"

    finding_types = (
        "SUBDOMAIN",
        "DNS_ASSET",
        "HOST",
    )

    # ========================================================================
    # Execution Policy
    # ========================================================================

    risk = "low"

    enabled_by_default = True

    requires_confirmation = False

    # ========================================================================
    # Configuration
    # ========================================================================

    supported_options = (
        "passive",
        "active",
        "bruteforce",
        "wordlist",
        "timeout",
    )

    default_options = {
        "passive": True,
    }

    # ========================================================================
    # Command Construction
    # ========================================================================

    def build_command(
        self,
        ctx: dict,
    ) -> list[str]:
        """
        Build the Amass command from runtime configuration.

        The adapter owns Amass-specific command construction.

        Returns:
            list[str]:
                Argument-safe command suitable for subprocess execution.
        """

        target = str(
            ctx.get(
                "target",
                "",
            )
        ).strip()

        if not target:
            raise ValueError(
                "Amass requires a target domain."
            )

        options = self.validate_options(
            ctx.get(
                "options",
                {},
            )
        )

        command = [
            "amass",
            "enum",
        ]

        if options.get(
            "passive",
            True,
        ):
            command.append(
                "-passive"
            )

        if options.get(
            "active",
            False,
        ):
            command.append(
                "-active"
            )

        if options.get(
            "bruteforce",
            False,
        ):
            command.append(
                "-brute"
            )

        wordlist = options.get(
            "wordlist"
        )

        if wordlist:
            command.extend(
                [
                    "-w",
                    str(wordlist),
                ]
            )

        timeout = options.get(
            "timeout"
        )

        if timeout:
            command.extend(
                [
                    "-timeout",
                    str(timeout),
                ]
            )

        command.extend(
            [
                "-d",
                target,
            ]
        )

        return command

    # ========================================================================
    # Execution
    # ========================================================================

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute Amass through the ScopeForgeX execution layer.

        The actual execution mechanism should be provided by the runtime
        execution service. The adapter is responsible for constructing the
        command and returning the standardized execution result.
        """

        command = self.build_command(
            ctx
        )

        # The execution service is not yet part of the new ToolBase contract.
        #
        # Do not introduce a second subprocess implementation here.
        #
        # During the execution-layer migration this method will delegate to
        # the canonical executor.

        raise NotImplementedError(
            "Amass execution is pending the new ScopeForgeX execution layer."
        )


__all__ = [
    "AmassTool",
]
