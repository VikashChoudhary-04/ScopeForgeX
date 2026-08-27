"""
ScopeForgeX Post-Assessment Tools
=================================

Capability-oriented post-assessment adapters.

Integrated capabilities:
    - Network pivoting / tunneling preparation
    - SOCKS proxy tunnel preparation

ScopeForgeX intentionally prepares post-assessment commands for authorized
operator review rather than executing them automatically.

Credential assessment belongs to the dedicated credential-assessment phase
and is therefore not implemented in this module.

v1.0.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import questionary

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.ui import ok


###############################################################################
# Helpers
###############################################################################


def _post_dir(
    ctx: dict[str, Any],
) -> Path:
    """
    Return the post-assessment output directory.
    """

    directory = (
        Path(ctx["outdir"])
        / "post"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _quote(
    value: str,
) -> str:
    """
    Safely quote a shell argument.
    """

    return shlex.quote(
        value
    )


def write_prepared_command(
    path: str | Path,
    title: str,
    command: str,
) -> None:
    """
    Append a prepared post-assessment command to the shared command file.
    """

    output = Path(
        path
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "a",
        encoding="utf-8",
    ) as outfile:

        outfile.write(
            "\n"
        )
        outfile.write(
            "=" * 80
            + "\n"
        )
        outfile.write(
            f"{title}\n"
        )
        outfile.write(
            "-" * 80
            + "\n"
        )
        outfile.write(
            command.strip()
        )
        outfile.write(
            "\n"
        )


###############################################################################
# Post-Assessment Preparation Adapter
###############################################################################


class PostAssessmentPrepTool(ToolBase):
    """
    Prepare a post-assessment command for manual operator review.

    ScopeForgeX does not automatically execute post-assessment operations.
    """

    phase = None

    input_type = "authorized_post_assessment_context"
    output_type = "prepared_command"

    finding_types = (
        "POST_ASSESSMENT_COMMAND",
    )

    risk = "high"

    enabled_by_default = False
    requires_confirmation = True

    def __init__(
        self,
        name: str,
        display_name: str,
        description: str,
        capability: str,
        template_cmd: str,
    ) -> None:

        self.name = name
        self.display_name = display_name
        self.description = description
        self.capability = capability
        self.template_cmd = template_cmd

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the operator-reviewable post-assessment command.
        """

        target = str(
            ctx.get(
                "target",
                "TARGET",
            )
        ).strip()

        return self.template_cmd.format(
            target=_quote(
                target
            )
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Prepare a post-assessment command after explicit confirmation.

        The command is written to an artifact and is never executed by this
        adapter.
        """

        post_dir = _post_dir(
            ctx
        )

        output_file = (
            post_dir
            / "prepared_commands.txt"
        )

        confirmed = questionary.confirm(
            f"Prepare command for: {self.display_name}?"
        ).ask()

        if not confirmed:

            return ExecutionResult.skipped(
                tool=self.name,
                capability=self.capability,
                reason=(
                    "Operator declined command preparation."
                ),
            )

        try:
            command = self.build_command(
                ctx
            )

        except (
            KeyError,
            ValueError,
        ) as exc:

            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        write_prepared_command(
            output_file,
            (
                f"{self.display_name} — "
                f"{self.description}"
            ),
            command,
        )

        ok(
            f"Prepared command saved for {self.display_name}"
        )

        result = ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
        )

        result.add_artifact(
            output_file
        )

        result.metadata.update(
            {
                "execution_mode": "manual",
                "command_prepared": True,
                "requires_confirmation": True,
            }
        )

        return result


###############################################################################
# Canonical Post-Assessment Tools
###############################################################################


ChiselPrepTool = PostAssessmentPrepTool(
    name="chisel",
    display_name="Chisel",
    description="Authorized network pivoting and reverse-tunneling preparation",
    capability="network_pivot_preparation",
    template_cmd=(
        "chisel server --reverse -p 8080"
    ),
)


SshSocksPrepTool = PostAssessmentPrepTool(
    name="ssh",
    display_name="SSH",
    description="Authorized SOCKS proxy tunnel preparation",
    capability="socks_proxy_preparation",
    template_cmd=(
        "ssh -D 1080 user@{target}"
    ),
)


###############################################################################
# Tool Registration
###############################################################################


ALL_STAGE5_POST_TOOLS = [
    ChiselPrepTool,
    SshSocksPrepTool,
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "PostAssessmentPrepTool",
    "ChiselPrepTool",
    "SshSocksPrepTool",
    "ALL_STAGE5_POST_TOOLS",
]
