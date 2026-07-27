"""
ScopeForgeX v0.5.0
Stage 5 - Post-Exploitation Preparation

ScopeForgeX intentionally does NOT execute
post-exploitation tools automatically.

Instead, this stage prepares reproducible
commands that an authorized operator may
review and execute manually.
"""

from __future__ import annotations

from pathlib import Path
import shlex

import questionary

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.ui import ok


###############################################################################
# Helper Functions
###############################################################################


def _post_directory(
    ctx: dict,
) -> Path:
    """
    Return the Stage-5 post directory.

    Creates it automatically if necessary.
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


def _prepared_commands_file(
    ctx: dict,
) -> Path:
    """
    Shared prepared command file.
    """

    return (
        _post_directory(ctx)
        / "prepared_commands.txt"
    )


def _quote(
    value: str,
) -> str:
    """
    Safely quote shell arguments.
    """

    return shlex.quote(
        value
    )


def _append_command(
    destination: Path,
    title: str,
    command: str,
) -> None:
    """
    Append a prepared command
    to the shared command file.
    """

    with destination.open(
        "a",
        encoding="utf-8",
    ) as outfile:

        outfile.write("\n")
        outfile.write("=" * 80)
        outfile.write("\n")

        outfile.write(title)
        outfile.write("\n")

        outfile.write("-" * 80)
        outfile.write("\n")

        outfile.write(
            command.strip()
        )

        outfile.write("\n")


###############################################################################
# Base Class
###############################################################################


class PostExploitationPreparationTool(ToolBase):
    """
    Shared Stage-5 functionality.
    """

    stage = 5
    risk = "high"

    def post_dir(
        self,
        ctx: dict,
    ) -> Path:

        return _post_directory(
            ctx
        )

    def prepared_file(
        self,
        ctx: dict,
    ) -> Path:

        return _prepared_commands_file(
            ctx
        )

    def build_command(
        self,
        ctx: dict,
    ) -> str:
        """
        Render command template.
        """

        return self.template_cmd.format(
            target=_quote(
                ctx.get(
                    "target",
                    "TARGET",
                )
            )
        )

    def save_command(
        self,
        ctx: dict,
        command: str,
    ) -> Path:

        output = self.prepared_file(
            ctx
        )

        _append_command(
            output,
            f"{self.name} — {self.description}",
            command,
        )

        return output


###############################################################################
# Post Preparation Tool
###############################################################################


class PostPrepTool(
    PostExploitationPreparationTool
):
    """
    Prepare reproducible post-exploitation
    commands for authorized manual execution.

    ScopeForgeX intentionally does not execute
    these tools automatically.
    """

    def __init__(
        self,
        name: str,
        description: str,
        template_cmd: str,
    ) -> None:

        self.name = name
        self.description = description
        self.template_cmd = template_cmd

    def confirm(
        self,
    ) -> bool:
        """
        Ask whether this command should be prepared.
        """

        return bool(
            questionary.confirm(
                f"Prepare command for {self.name}?"
            ).ask()
        )

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        if not self.confirm():

            return ExecutionResult.skipped(
                tool=self.name,
                capability=(
                    "post_exploitation_preparation"
                ),
                reason="Skipped by user",
            )

        command = self.build_command(
            ctx
        )

        output = self.save_command(
            ctx,
            command,
        )

        ok(
            f"Prepared command written for "
            f"{self.name}"
        )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=(
                "post_exploitation_preparation"
            ),
            artifacts=[
                output,
            ],
            metadata={
                "message": (
                    "Prepared command saved for "
                    "manual execution."
                ),
                "execution_mode": "manual",
            },
        )


###############################################################################
# Built-in Post-Exploitation Templates
###############################################################################


CHISEL_TEMPLATE = (
    "chisel server "
    "--reverse "
    "-p 8080"
)


SSH_TEMPLATE = (
    "ssh "
    "-D 1080 "
    "user@TARGET_IP"
)


HYDRA_TEMPLATE = (
    "hydra "
    "-l admin "
    "-P /path/to/passwords.txt "
    "{target} "
    "http-post-form "
    "\"/login:"
    "username=^USER^&"
    "password=^PASS^:"
    "Invalid\""
)


MEDUSA_TEMPLATE = (
    "medusa "
    "-h {target} "
    "-u admin "
    "-P /path/to/passwords.txt "
    "-M http"
)


HASHCAT_TEMPLATE = (
    "hashcat "
    "-m 0 "
    "-a 0 "
    "hashes.txt "
    "/path/to/wordlist.txt"
)


JOHN_TEMPLATE = (
    "john "
    "--wordlist=/path/to/wordlist.txt "
    "hashes.txt"
)


###############################################################################
# Tool Registration
###############################################################################


ALL_STAGE5_POST_TOOLS = [
    PostPrepTool(
        name="chisel",
        description="Pivoting / tunneling",
        template_cmd=CHISEL_TEMPLATE,
    ),
    PostPrepTool(
        name="ssh",
        description="SOCKS proxy tunnel",
        template_cmd=SSH_TEMPLATE,
    ),
    PostPrepTool(
        name="hydra",
        description="Credential attack (rate-limit required)",
        template_cmd=HYDRA_TEMPLATE,
    ),
    PostPrepTool(
        name="medusa",
        description="Credential attack (rate-limit required)",
        template_cmd=MEDUSA_TEMPLATE,
    ),
    PostPrepTool(
        name="hashcat",
        description="Offline hash cracking",
        template_cmd=HASHCAT_TEMPLATE,
    ),
    PostPrepTool(
        name="john",
        description="Offline password cracking",
        template_cmd=JOHN_TEMPLATE,
    ),
]


###############################################################################
# Public Exports
###############################################################################


__all__ = [
    "PostExploitationPreparationTool",
    "PostPrepTool",
    "CHISEL_TEMPLATE",
    "SSH_TEMPLATE",
    "HYDRA_TEMPLATE",
    "MEDUSA_TEMPLATE",
    "HASHCAT_TEMPLATE",
    "JOHN_TEMPLATE",
    "ALL_STAGE5_POST_TOOLS",
]
