"""
ScopeForgeX Web Reconnaissance Tools
====================================

Native 3.0 adapters for web-oriented reconnaissance tools.

Tools
-----

- Subhunt

Architecture
------------

Workflow Engine
    |
    v
Tool Registry
    |
    v
ToolContext
    |
    v
Subhunt ToolAdapter
    |
    +-- ToolDefinition
    +-- option validation
    +-- target normalization
    +-- command construction
    +-- result normalization
    +-- artifact preservation
    |
    v
ToolExecutor
    |
    v
Execution Layer

The adapter owns Subhunt-specific command construction and the narrowly
defined normalization of Subhunt's known completed-scan exit status.

Subprocess execution remains the responsibility of the ScopeForgeX execution
layer.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolDefinition,
    ToolOption,
)
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Constants
###############################################################################


DEFAULT_WORDLIST = (
    "/usr/share/wordlists/seclists/"
    "Discovery/DNS/subdomains-top1million-5000.txt"
)


###############################################################################
# Subhunt
###############################################################################


class SubhuntTool(
    ToolAdapter
):
    """
    Subhunt active subdomain-enumeration adapter.

    Workflow targets may be supplied as URLs, hostnames, or host:port values.
    Subhunt itself expects a hostname/domain, so the adapter normalizes the
    target before constructing the command.

    Subhunt v1.3.0 returns exit code 1 when a scan completes without
    findings. Because ScopeForgeX deliberately uses ``--quiet`` for
    automation, the adapter must not depend on an interactive completion
    marker such as ``Scan Finished``.
    """

    definition = ToolDefinition(
        name="subhunt",
        capability="subdomain_discovery",
        phase="reconnaissance",
        purpose="Active wordlist-based subdomain discovery.",
        executable="subhunt",
        input_type="domain",
        output_type="raw",
        finding_types=(
            "SUBDOMAIN",
        ),
        dependencies=(
            "subhunt",
        ),
        options=(
            ToolOption(
                name="wordlist",
                flag="--bruteforce",
                description=(
                    "Wordlist used for active subdomain discovery."
                ),
                option_type="path",
                default=DEFAULT_WORDLIST,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="threads",
                flag="--threads",
                description="Number of concurrent Subhunt workers.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="timeout",
                flag="--timeout",
                description="Subhunt execution timeout.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    @staticmethod
    def _target_hostname(
        target: str,
    ) -> str:
        """
        Normalize a workflow target into the hostname expected by Subhunt.

        Examples:

            http://example.com -> example.com
            https://example.com -> example.com
            example.com        -> example.com
            example.com:443    -> example.com
        """

        value = str(
            target
        ).strip()

        if not value:
            raise ValueError(
                "Subhunt target cannot be empty."
            )

        parsed = (
            urlparse(
                value
            )
            if "://" in value
            else urlparse(
                f"//{value}"
            )
        )

        hostname = parsed.hostname

        if not hostname:
            raise ValueError(
                f"Could not determine hostname from Subhunt target: "
                f"{target!r}"
            )

        return hostname

    def validate_options(
        self,
    ) -> None:
        """
        Validate Subhunt-specific options.
        """

        super().validate_options()

        wordlist = self.get_option(
            "wordlist",
        )

        if wordlist is None:
            wordlist = DEFAULT_WORDLIST

        wordlist_path = Path(
            str(wordlist).strip()
        )

        if not str(
            wordlist_path
        ):
            raise ValueError(
                "Subhunt wordlist cannot be empty."
            )

        if not wordlist_path.is_file():
            raise ValueError(
                f"Subhunt wordlist does not exist or is not a file: "
                f"{wordlist_path}"
            )

        for name in (
            "threads",
            "timeout",
        ):
            value = self.get_option(
                name
            )

            if value is None:
                continue

            self._validate_positive_integer(
                name,
                value,
            )

    def build_arguments(
        self,
    ) -> list[str]:
        """
        Build Subhunt-specific command-line arguments.
        """

        self.validate_options()

        arguments: list[str] = [
            "-d",
            self._target_hostname(
                self.context.target
            ),
        ]

        wordlist = self.get_option(
            "wordlist",
        )

        if wordlist is None:
            wordlist = DEFAULT_WORDLIST

        arguments.extend(
            [
                "--bruteforce",
                str(wordlist),
                "--quiet",
            ]
        )

        threads = self.get_option(
            "threads"
        )

        if threads is not None:
            arguments.extend(
                [
                    "--threads",
                    str(threads),
                ]
            )

        timeout = self.get_option(
            "timeout"
        )

        if timeout is not None:
            arguments.extend(
                [
                    "--timeout",
                    str(timeout),
                ]
            )

        return arguments

    @staticmethod
    def _validate_positive_integer(
        name: str,
        value: Any,
    ) -> None:
        """
        Validate an integer execution-control option.
        """

        if (
            not isinstance(
                value,
                int,
            )
            or isinstance(
                value,
                bool,
            )
        ):
            raise TypeError(
                f"Subhunt {name} must be an integer."
            )

        if value <= 0:
            raise ValueError(
                f"Subhunt {name} must be greater than zero."
            )

    @staticmethod
    def _execution_timeout(
        context: Any,
        default: int,
    ) -> int:
        """
        Return the canonical execution timeout for a direct/custom run.

        ToolExecutor propagates the assessment-level timeout into
        ToolContext.options["tool_timeout"] before invoking a custom
        adapter. The adapter-specific default remains available for
        direct adapter execution outside ToolExecutor.
        """

        options = getattr(
            context,
            "options",
            None,
        )

        if not isinstance(
            options,
            dict,
        ):
            return default

        value = options.get(
            "tool_timeout",
            default,
        )

        try:
            timeout = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return default

        if timeout <= 0:
            return default

        return timeout

    @staticmethod
    def _strip_ansi(
        value: str,
    ) -> str:
        """
        Remove ANSI terminal escape sequences from text.
        """

        return re.sub(
            r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])",
            "",
            value,
        )

    @classmethod
    def normalize_result(
        cls,
        result: ExecutionResult,
    ) -> ExecutionResult:
        """
        Normalize Subhunt's completed-scan exit status.

        Subhunt v1.3.0 uses exit code 1 for a completed scan with no
        findings. ScopeForgeX always invokes Subhunt with ``--quiet``, so
        completion must not depend on the interactive ``Scan Finished``
        marker used by older output behavior.

        Exit code 1 is normalized only when the generated quiet command
        completed without tool error output. Other non-zero results remain
        failures.
        """

        exit_code = result.metadata.get(
            "exit_code"
        )

        if exit_code != 1:
            return result

        output_parts = [
            str(
                getattr(
                    result,
                    "stdout",
                    "",
                )
                or ""
            ),
            str(
                getattr(
                    result,
                    "stderr",
                    "",
                )
                or ""
            ),
        ]

        outfile = result.metadata.get(
            "outfile"
        )

        if outfile:
            try:
                output_parts.append(
                    Path(
                        str(outfile)
                    ).read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                )
            except OSError:
                pass

        normalized_output = cls._strip_ansi(
            "\n".join(
                output_parts
            )
        )

        command = result.metadata.get(
            "command",
            []
        )

        if not isinstance(command, (list, tuple)):
            command = []

        has_quiet_mode = "--quiet" in command

        # Subhunt v1.3.0 documents exit code 1 for a completed scan with
        # no findings. ScopeForgeX always supplies --quiet, so an empty
        # result with no tool error output represents a valid zero-result
        # assessment rather than an execution failure.
        if (
            not has_quiet_mode
            or normalized_output.strip()
        ):
            return result

        result.success = True

        result.errors = [
            error
            for error in result.errors
            if error != "Command exited with status 1."
        ]

        result.metadata.update(
            {
                "subhunt_exit_code_normalized": True,
                "subhunt_original_exit_code": 1,
                "subhunt_completion_detected": True,
            }
        )

        return result

    def run(
        self,
    ) -> ExecutionResult:
        """
        Execute Subhunt through the ScopeForgeX execution layer.

        This method remains available for direct adapter execution and
        delegates result normalization through ``normalize_result()``.
        """

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="subhunt not installed",
            )

        recon_dir = (
            self.context.output_dir
            / "recon"
        )

        recon_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = (
            recon_dir
            / "subhunt.txt"
        )

        log_file = (
            recon_dir
            / "subhunt.log"
        )

        try:
            command = self.build_command()

        except (
            TypeError,
            ValueError,
        ) as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=self._execution_timeout(
                self.context,
                600,
            ),
        )

        result.metadata.setdefault(
            "outfile",
            str(log_file),
        )

        result = self.normalize_result(
            result
        )

        if log_file.exists():
            try:
                log_output = log_file.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                log_output = ""
        else:
            log_output = ""

        output_content = (
            result.stdout
            or result.stderr
            or log_output
            or ""
        )

        output_file.write_text(
            str(
                output_content
            ),
            encoding="utf-8",
        )

        result.add_artifact(
            str(
                log_file
            )
        )

        result.add_artifact(
            str(
                output_file
            )
        )

        result.metadata.update(
            {
                "target": self.context.target,
                "normalized_target": self._target_hostname(
                    self.context.target
                ),
                "output_file": str(
                    output_file
                ),
                "command": command,
            }
        )

        return result


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SubhuntTool",
]
