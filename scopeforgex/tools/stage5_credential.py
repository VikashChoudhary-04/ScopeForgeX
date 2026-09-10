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
from urllib.parse import urlparse

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


def _normalize_hydra_target(
    target: str,
) -> str:
    """
    Normalize a workflow target into the host representation expected by
    Hydra's classic TARGET SERVICE command form.

    Supported forms include:

        example.com
        example.com:22
        127.0.0.1
        127.0.0.1:2222
        http://example.com
        https://example.com:443
        [::1]:22

    The workflow target itself is never modified.
    """

    value = str(
        target
    ).strip()

    if not value:
        raise ValueError(
            "Hydra requires an authentication target."
        )

    parsed = urlparse(
        value
    )

    if parsed.scheme and parsed.hostname:
        return parsed.hostname

    if value.startswith("["):
        closing = value.find(
            "]"
        )

        if closing != -1:
            return value[
                1:closing
            ]

    if value.count(":") == 1:
        host, port = value.rsplit(
            ":",
            1,
        )

        if port.isdigit() and host.strip():
            return host.strip()

    return value


def _hydra_target_port(
    target: str,
) -> int | None:
    """
    Return an explicit port from a Hydra workflow target.

    Supported forms include:

        example.com:22
        127.0.0.1:2222
        http://example.com:443
        https://example.com:443
        [::1]:22
    """

    value = str(
        target
    ).strip()

    if not value:
        return None

    parsed = urlparse(
        value
    )

    if parsed.port is not None:
        return parsed.port

    if value.startswith("["):
        closing = value.find(
            "]"
        )

        if (
            closing != -1
            and len(value) > closing + 1
            and value[closing + 1] == ":"
        ):
            port = value[
                closing + 2:
            ]

            if port.isdigit():
                return int(
                    port
                )

        return None

    if value.count(":") == 1:
        _, port = value.rsplit(
            ":",
            1,
        )

        if port.isdigit():
            return int(
                port
            )

    return None


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

        if not username and not username_file:
            raise ValueError(
                "Hydra requires either username or username_file."
            )

        if not password_file:
            raise ValueError(
                "Hydra requires password_file."
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
            username_path = Path(
                str(username_file)
            ).expanduser()

            if not username_path.is_file():
                raise ValueError(
                    f"Hydra username_file not found: "
                    f"{username_path}"
                )

        password_path = Path(
            str(password_file)
        ).expanduser()

        if not password_path.is_file():
            raise ValueError(
                f"Hydra password_file not found: "
                f"{password_path}"
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

        target = str(
            self.context.target
        ).strip()

        if not target:
            raise ValueError(
                "Hydra requires an authentication target."
            )

        service_values = [
            str(value).strip()
            for value in self.context.input_data
            if value is not None
            and str(value).strip()
        ]

        if not service_values:
            raise ValueError(
                "Hydra requires an authentication service in "
                "ToolContext.input_data."
            )

    def build_arguments(self) -> list[str]:
        """
        Build Hydra command arguments.

        Hydra requires a target and authentication service. The service is
        supplied through ToolContext.input_data.

        When the workflow target contains an explicit port, the port is
        supplied through Hydra's -s option while the target itself is
        normalized to its host representation.
        """

        self.validate_options()

        options = _resolved_options(
            self
        )

        target = _normalize_hydra_target(
            self.context.target
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

        arguments.extend(
            [
                "-P",
                str(password_file),
                "-t",
                str(threads),
            ]
        )

        target_port = _hydra_target_port(
            self.context.target
        )

        if target_port is not None:
            arguments.extend(
                [
                    "-s",
                    str(target_port),
                ]
            )

        arguments.extend(
            [
                target,
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

        configured_timeout = self.context.options.get(
            "tool_timeout"
        )

        if configured_timeout is None:
            configured_timeout = 900

        try:
            execution_timeout = int(
                configured_timeout
            )
        except (
            TypeError,
            ValueError,
        ):
            execution_timeout = 900

        if execution_timeout <= 0:
            execution_timeout = 900

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=execution_timeout,
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
                "network_target": _normalize_hydra_target(
                    self.context.target
                ),
                "target_port": _hydra_target_port(
                    self.context.target
                ),
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

    ScopeForgeX deliberately uses Hashcat's dictionary attack mode here so
    command construction remains deterministic and the required attack input
    is unambiguous.

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
            ToolOption(
                name="wordlist",
                flag=None,
                description="Dictionary wordlist used for the attack.",
                option_type="path",
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

        if hash_type is None:
            raise ValueError(
                "Hashcat requires a hash_type option."
            )

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

        wordlist = self.get_option(
            "wordlist"
        )

        if not wordlist:
            raise ValueError(
                "Hashcat requires a wordlist."
            )

        wordlist_path = Path(
            str(wordlist)
        ).expanduser()

        if not wordlist_path.is_file():
            raise ValueError(
                f"Hashcat wordlist not found: {wordlist_path}"
            )

    def build_arguments(self) -> list[str]:
        """
        Build a deterministic Hashcat dictionary-attack command.

        The hash file is the first ToolContext.input_data item.
        The wordlist is supplied through the ``wordlist`` option.

        Hashcat attack mode 0 is used explicitly because it accepts a
        dictionary input and provides a deterministic command shape.
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
        ).expanduser()

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

        wordlist = self.get_option(
            "wordlist"
        )

        return [
            "-m",
            str(hash_type),
            "-a",
            "0",
            str(hash_file),
            str(wordlist),
        ]

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

        configured_timeout = self.context.options.get(
            "tool_timeout"
        )

        if configured_timeout is None:
            configured_timeout = 1800

        try:
            execution_timeout = int(
                configured_timeout
            )
        except (
            TypeError,
            ValueError,
        ):
            execution_timeout = 1800

        if execution_timeout <= 0:
            execution_timeout = 1800

        result = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(log_file),
            timeout=execution_timeout,
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
