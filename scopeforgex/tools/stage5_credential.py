"""
ScopeForgeX
Stage 5 — Credential Assessment
===============================

Provides the canonical credential-assessment adapters:

- Hydra
- Hashcat

Credential assessment is explicitly selectable and is not part of the
default assessment pipeline.

The adapters own command construction and delegate process execution to the
ScopeForgeX execution layer.

Collectors remain responsible for parsing and normalization.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolDefinition,
    ToolOption,
    ToolContext,
)
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Helpers
###############################################################################


def _resolved_options(
    adapter: ToolAdapter,
) -> dict[str, Any]:
    """
    Return tool defaults merged with explicit ToolContext options.
    """

    values = {
        option.name: option.default
        for option in adapter.options
        if option.default is not None
    }

    values.update(
        adapter.context.options
    )

    return values


def _write_raw_output(
    result: ExecutionResult,
    output_file: Path,
) -> None:
    """Preserve raw process output in a deterministic artifact."""

    stdout = getattr(
        result,
        "stdout",
        "",
    )

    stderr = getattr(
        result,
        "stderr",
        "",
    )

    sections: list[str] = []

    if stdout:
        sections.append(
            str(stdout)
        )

    if stderr:
        sections.append(
            str(stderr)
        )

    output_file.write_text(
        "\n".join(sections),
        encoding="utf-8",
    )


###############################################################################
# Hydra
###############################################################################


class HydraTool(
    ToolAdapter
):
    """
    Authorized online credential-assessment adapter.

    Hydra commands are constructed by the adapter and executed only when the
    surrounding workflow explicitly invokes this tool.
    """

    definition = ToolDefinition(
        name="hydra",
        capability="authentication_testing",
        phase="credential_assessment",
        purpose="Authorized online authentication testing.",
        executable="hydra",
        input_type="authentication_target",
        output_type="raw",
        finding_types=(
            "AUTHENTICATION_TEST",
        ),
        dependencies=(
            "hydra",
        ),
        options=(
            ToolOption(
                name="username",
                flag="-l",
                description="Single username for authentication testing.",
                option_type="string",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="username_file",
                flag="-L",
                description="Username file.",
                option_type="path",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="password_file",
                flag="-P",
                description="Password file.",
                option_type="path",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="threads",
                flag="-t",
                description="Hydra task count.",
                option_type="integer",
                default=1,
                safe=True,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(self) -> None:
        """Validate Hydra command options."""

        super().validate_options()

        options = _resolved_options(
            self
        )

        username = options.get(
            "username"
        )

        username_file = options.get(
            "username_file"
        )

        password_file = options.get(
            "password_file"
        )

        if username and username_file:
            raise ValueError(
                "Hydra cannot use both username and username_file."
            )

        if username is not None:
            username = str(
                username
            ).strip()

            if not username:
                raise ValueError(
                    "Hydra username cannot be empty."
                )

        if username_file:
            if not Path(
                str(username_file)
            ).is_file():
                raise ValueError(
                    f"Hydra username_file not found: "
                    f"{username_file}"
                )

        if password_file:
            if not Path(
                str(password_file)
            ).is_file():
                raise ValueError(
                    f"Hydra password_file not found: "
                    f"{password_file}"
                )

        threads = options.get(
            "threads",
            1,
        )

        try:
            threads = int(
                threads
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "Hydra threads must be an integer."
            ) from exc

        if threads <= 0:
            raise ValueError(
                "Hydra threads must be greater than zero."
            )

    def build_arguments(self) -> list[str]:
        """
        Build Hydra command arguments.

        Hydra requires a target and authentication service. The service is
        supplied through ToolContext.input_data when available, otherwise the
        first input element is interpreted as the service.
        """

        self.validate_options()

        options = _resolved_options(
            self
        )

        if not self.context.target:
            raise ValueError(
                "Hydra requires an authentication target."
            )

        if not self.context.input_data:
            raise ValueError(
                "Hydra requires an authentication service in "
                "ToolContext.input_data."
            )

        service = str(
            self.context.input_data[0]
        ).strip()

        if not service:
            raise ValueError(
                "Hydra authentication service cannot be empty."
            )

        username = options.get(
            "username"
        )

        username_file = options.get(
            "username_file"
        )

        password_file = options.get(
            "password_file"
        )

        threads = int(
            options.get(
                "threads",
                1,
            )
        )

        arguments: list[str] = []

        if username:
            arguments.extend(
                [
                    "-l",
                    str(username),
                ]
            )

        elif username_file:
            arguments.extend(
                [
                    "-L",
                    str(username_file),
                ]
            )

        if password_file:
            arguments.extend(
                [
                    "-P",
                    str(password_file),
                ]
            )

        arguments.extend(
            [
                "-t",
                str(threads),
                self.context.target,
                service,
            ]
        )

        return arguments

    def run(self) -> ExecutionResult:
        """Execute Hydra and pass the result through HydraCollector."""

        from scopeforgex.collectors.hydra import (
            HydraCollector,
        )

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="hydra not installed",
            )

        credential_dir = (
            self.context.output_dir
            / "credential"
        )

        credential_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = (
            credential_dir
            / "hydra.txt"
        )

        log_file = (
            credential_dir
            / "hydra.log"
        )

        command = self.build_command()

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=900,
        )

        _write_raw_output(
            result,
            output_file,
        )

        result.add_artifact(
            output_file
        )

        if log_file.exists():
            result.add_artifact(
                log_file
            )

        try:
            collector = HydraCollector()

            collected = collector.collect(
                target=self.context.target,
                options={
                    "result": result,
                    "command": command,
                    "target": self.context.target,
                },
            )

            result.metadata.update(
                {
                    "collector": "HydraCollector",
                    "collector_result": collected,
                }
            )

        except Exception as exc:
            result.add_warning(
                f"Hydra collection failed: {exc}"
            )

        result.metadata.update(
            {
                "target": self.context.target,
                "command_executed": True,
                "output_file": str(
                    output_file
                ),
            }
        )

        return result


###############################################################################
# Hashcat
###############################################################################


class HashcatTool(
    ToolAdapter
):
    """
    Authorized offline password/hash assessment adapter.

    Hashcat output is parsed by HashcatCollector.
    """

    definition = ToolDefinition(
        name="hashcat",
        capability="password_hash_assessment",
        phase="credential_assessment",
        purpose="Authorized offline password and hash assessment.",
        executable="hashcat",
        input_type="hash_file",
        output_type="raw",
        finding_types=(
            "PASSWORD_SECURITY",
            "HASH_SECURITY",
        ),
        dependencies=(
            "hashcat",
        ),
        options=(
            ToolOption(
                name="hash_type",
                flag="-m",
                description="Hashcat hash mode/type.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(self) -> None:
        """Validate Hashcat options."""

        super().validate_options()

        hash_type = self.get_option(
            "hash_type"
        )

        if hash_type is not None:
            try:
                hash_type = int(
                    hash_type
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise ValueError(
                    "Hashcat hash_type must be an integer."
                ) from exc

            if hash_type < 0:
                raise ValueError(
                    "Hashcat hash_type cannot be negative."
                )

    def build_arguments(self) -> list[str]:
        """
        Build Hashcat command arguments.

        The hash file is the first ToolContext.input_data item.
        """

        self.validate_options()

        if not self.context.input_data:
            raise ValueError(
                "Hashcat requires a hash file in ToolContext.input_data."
            )

        hash_file = Path(
            str(
                self.context.input_data[0]
            )
        )

        if not hash_file.is_file():
            raise ValueError(
                f"Hashcat hash file not found: {hash_file}"
            )

        hash_type = self.get_option(
            "hash_type"
        )

        if hash_type is None:
            raise ValueError(
                "Hashcat requires a hash_type option."
            )

        arguments = [
            "-m",
            str(hash_type),
            str(hash_file),
        ]

        return arguments

    def run(self) -> ExecutionResult:
        """Execute Hashcat and parse the resulting output."""

        from scopeforgex.collectors.hashcat import (
            HashcatCollector,
        )

        if not is_tool_installed(
            self.executable
        ):
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="hashcat not installed",
            )

        credential_dir = (
            self.context.output_dir
            / "credential"
        )

        credential_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_file = (
            credential_dir
            / "hashcat.txt"
        )

        log_file = (
            credential_dir
            / "hashcat.log"
        )

        command = self.build_command()

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=1800,
        )

        _write_raw_output(
            result,
            output_file,
        )

        result.add_artifact(
            output_file
        )

        if log_file.exists():
            result.add_artifact(
                log_file
            )

        try:
            collector = HashcatCollector()

            observations = collector.collect(
                getattr(
                    result,
                    "stdout",
                    "",
                ),
                target=self.context.target,
                hash_type=self.get_option(
                    "hash_type"
                ),
            )

            result.metadata.update(
                {
                    "collector": "HashcatCollector",
                    "observation_count": len(
                        observations
                    ),
                    "observations": [
                        observation.as_dict()
                        for observation in observations
                    ],
                }
            )

        except Exception as exc:
            result.add_warning(
                f"Hashcat collection failed: {exc}"
            )

        result.metadata.update(
            {
                "target": self.context.target,
                "command_executed": True,
                "output_file": str(
                    output_file
                ),
            }
        )

        return result


###############################################################################
# Stage 5 Tool Collection
###############################################################################


ALL_STAGE5_CREDENTIAL_TOOLS = [
    HydraTool,
    HashcatTool,
]


###############################################################################
# Public API
###############################################################################


__all__ = [
    "HydraTool",
    "HashcatTool",
    "ALL_STAGE5_CREDENTIAL_TOOLS",
]
