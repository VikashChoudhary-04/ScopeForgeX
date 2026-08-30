"""
ScopeForgeX
Stage 2 — Web Enumeration Tools
================================

Native ToolAdapter implementations for the canonical Stage 2 web-enumeration
toolset:

- HTTPX
- Katana
- FFUF
- WhatWeb
- Kiterunner
- JSLuice

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
ToolAdapter
    |
    +-- option validation
    +-- command construction
    +-- command arguments
    |
    v
ToolExecutor
    |
    v
ExecutionResult

The adapters own tool-specific command construction.

Subprocess execution remains the responsibility of the ScopeForgeX execution
layer.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scopeforgex.registry.tool_base import (
    ToolAdapter,
    ToolDefinition,
    ToolOption,
)


###############################################################################
# HTTPX
###############################################################################


class HttpxTool(ToolAdapter):
    """
    HTTP service probing and metadata collection.
    """

    definition = ToolDefinition(
        name="httpx",
        capability="http_service_enumeration",
        phase="enumeration",
        purpose=(
            "Determine which discovered hosts expose HTTP services and "
            "collect status, title, server and technology information."
        ),
        executable="httpx",
        input_type="url",
        output_type="raw",
        finding_types=(
            "HTTP_SERVICE",
            "HTTP_STATUS",
            "WEB_SERVER",
        ),
        dependencies=(
            "httpx",
        ),
        options=(
            ToolOption(
                name="status_code",
                flag="-status-code",
                description="Display HTTP response status codes.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="title",
                flag="-title",
                description="Display page titles.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="server",
                flag="-server",
                description="Display HTTP server information.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="technology",
                flag="-tech-detect",
                description="Enable technology detection.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="follow_redirects",
                flag="-follow-redirects",
                description="Follow HTTP redirects.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=False,
    )

    def validate_options(self) -> None:
        """Validate HTTPX options."""

        super().validate_options()

        for name in (
            "status_code",
            "title",
            "server",
            "technology",
            "follow_redirects",
        ):
            if not self.has_option(name):
                continue

            value = self.get_option(name)

            if not isinstance(value, bool):
                raise TypeError(
                    f"{name} option for HTTPX must be boolean."
                )

    def build_arguments(self) -> list[str]:
        """Build HTTPX-specific command-line arguments."""

        self.validate_options()

        arguments: list[str] = []

        if self.get_option(
            "status_code",
            True,
        ):
            arguments.append(
                "-status-code"
            )

        if self.get_option(
            "title",
            True,
        ):
            arguments.append(
                "-title"
            )

        if self.get_option(
            "server",
            True,
        ):
            arguments.append(
                "-server"
            )

        if self.get_option(
            "technology",
            True,
        ):
            arguments.append(
                "-tech-detect"
            )

        if self.get_option(
            "follow_redirects",
            False,
        ):
            arguments.append(
                "-follow-redirects"
            )

        arguments.extend(
            [
                "-silent",
                "-u",
                self.context.target,
            ]
        )

        return arguments


###############################################################################
# KATANA
###############################################################################


class KatanaTool(ToolAdapter):
    """
    Web crawler and endpoint discovery adapter.
    """

    definition = ToolDefinition(
        name="katana",
        capability="web_crawling",
        phase="enumeration",
        purpose=(
            "Discover URLs, endpoints, parameters, forms and web resources."
        ),
        executable="katana",
        input_type="url",
        output_type="raw",
        finding_types=(
            "URL",
            "ENDPOINT",
            "PARAMETER",
            "FORM",
            "RESOURCE",
        ),
        dependencies=(
            "katana",
        ),
        options=(
            ToolOption(
                name="depth",
                flag="-d",
                description="Maximum crawl depth.",
                option_type="integer",
                default=2,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="js_crawl",
                flag="-jc",
                description="Enable JavaScript crawling.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
            ToolOption(
                name="known_files",
                flag="-kf",
                description="Crawl known files.",
                option_type="boolean",
                default=False,
                safe=False,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(self) -> None:
        """Validate Katana options."""

        super().validate_options()

        depth = self.get_option(
            "depth",
            2,
        )

        if (
            not isinstance(depth, int)
            or isinstance(depth, bool)
        ):
            raise TypeError(
                "Katana depth must be an integer."
            )

        if depth <= 0:
            raise ValueError(
                "Katana depth must be greater than zero."
            )

        for name in (
            "js_crawl",
            "known_files",
        ):
            value = self.get_option(
                name,
                False,
            )

            if not isinstance(value, bool):
                raise TypeError(
                    f"Katana {name} must be boolean."
                )

    def build_arguments(self) -> list[str]:
        """Build Katana-specific command-line arguments."""

        self.validate_options()

        arguments = [
            "-u",
            self.context.target,
            "-d",
            str(
                self.get_option(
                    "depth",
                    2,
                )
            ),
            "-silent",
        ]

        if self.get_option(
            "js_crawl",
            False,
        ):
            arguments.append(
                "-jc"
            )

        if self.get_option(
            "known_files",
            False,
        ):
            arguments.extend(
                [
                    "-kf",
                    "all",
                ]
            )

        return arguments


###############################################################################
# FFUF
###############################################################################


def _find_default_web_fuzz_wordlist() -> Path | None:
    """
    Resolve the default web-content wordlist.

    The helper is intentionally local to the adapter layer so FFUF remains
    self-contained.
    """

    candidates = (
        Path(
            "/usr/share/seclists/Discovery/Web-Content/"
            "directory-list-2.3-small.txt"
        ),
        Path(
            "/usr/share/wordlists/"
            "dirb/common.txt"
        ),
    )

    for path in candidates:
        if path.is_file():
            return path

    return None


class FfufTool(ToolAdapter):
    """
    Content, directory and parameter discovery using FFUF.
    """

    definition = ToolDefinition(
        name="ffuf",
        capability="content_discovery",
        phase="enumeration",
        purpose=(
            "Discover hidden endpoints, directories, files, parameters and "
            "virtual hosts."
        ),
        executable="ffuf",
        input_type="url",
        output_type="raw",
        finding_types=(
            "HIDDEN_ENDPOINT",
            "DIRECTORY",
            "FILE",
            "PARAMETER",
            "VHOST",
        ),
        dependencies=(
            "ffuf",
        ),
        options=(
            ToolOption(
                name="wordlist",
                flag="-w",
                description="Wordlist used for content discovery.",
                option_type="path",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="threads",
                flag="-t",
                description="Number of FFUF worker threads.",
                option_type="integer",
                default=None,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="match_codes",
                flag="-mc",
                description="HTTP status codes to match.",
                option_type="string",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="filter_codes",
                flag="-fc",
                description="HTTP status codes to filter.",
                option_type="string",
                default=None,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="rate",
                flag="-rate",
                description="Maximum requests per second.",
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
        """Validate FFUF options."""

        super().validate_options()

        threads = self.get_option(
            "threads"
        )

        if threads is not None:
            if (
                not isinstance(threads, int)
                or isinstance(threads, bool)
            ):
                raise TypeError(
                    "FFUF threads must be an integer."
                )

            if threads <= 0:
                raise ValueError(
                    "FFUF threads must be greater than zero."
                )

        rate = self.get_option(
            "rate"
        )

        if rate is not None:
            if (
                not isinstance(rate, int)
                or isinstance(rate, bool)
            ):
                raise TypeError(
                    "FFUF rate must be an integer."
                )

            if rate < 0:
                raise ValueError(
                    "FFUF rate cannot be negative."
                )

        for name in (
            "wordlist",
            "match_codes",
            "filter_codes",
        ):
            value = self.get_option(
                name
            )

            if value is not None:
                value = str(
                    value
                ).strip()

                if not value:
                    raise ValueError(
                        f"FFUF {name} cannot be empty."
                    )

    def _resolve_wordlist(self) -> str:
        """Resolve the configured or default FFUF wordlist."""

        wordlist = self.get_option(
            "wordlist"
        )

        if wordlist is not None:
            path = Path(
                str(wordlist)
            ).expanduser()

            if not path.is_file():
                raise ValueError(
                    f"Invalid FFUF wordlist: {path}"
                )

            return str(
                path
            )

        default = _find_default_web_fuzz_wordlist()

        if default is None:
            raise ValueError(
                "FFUF requires a valid wordlist."
            )

        return str(
            default
        )

    def build_arguments(self) -> list[str]:
        """Build FFUF-specific command-line arguments."""

        self.validate_options()

        target = self.context.target

        if "FUZZ" not in target:
            if target.endswith("/"):
                target += "FUZZ"
            else:
                target += "/FUZZ"

        arguments = [
            "-u",
            target,
            "-w",
            self._resolve_wordlist(),
            "-noninteractive",
        ]

        threads = self.get_option(
            "threads"
        )

        if threads is not None:
            arguments.extend(
                [
                    "-t",
                    str(threads),
                ]
            )

        match_codes = self.get_option(
            "match_codes"
        )

        if match_codes:
            arguments.extend(
                [
                    "-mc",
                    str(match_codes),
                ]
            )

        filter_codes = self.get_option(
            "filter_codes"
        )

        if filter_codes:
            arguments.extend(
                [
                    "-fc",
                    str(filter_codes),
                ]
            )

        rate = self.get_option(
            "rate"
        )

        if rate:
            arguments.extend(
                [
                    "-rate",
                    str(rate),
                ]
            )

        return arguments


###############################################################################
# WHATWEB
###############################################################################


class WhatWebTool(ToolAdapter):
    """
    Website technology fingerprinting.
    """

    definition = ToolDefinition(
        name="whatweb",
        capability="technology_fingerprinting",
        phase="enumeration",
        purpose=(
            "Identify technologies, frameworks, CMS platforms, servers and "
            "libraries exposed by web applications."
        ),
        executable="whatweb",
        input_type="url",
        output_type="raw",
        finding_types=(
            "TECHNOLOGY",
            "FRAMEWORK",
            "CMS",
            "SERVER",
            "LIBRARY",
        ),
        dependencies=(
            "whatweb",
        ),
        options=(
            ToolOption(
                name="aggression",
                flag="-a",
                description="WhatWeb aggression level.",
                option_type="integer",
                default=1,
                choices=(
                    1,
                    2,
                    3,
                    4,
                ),
                safe=True,
                aggressive=True,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(self) -> None:
        """Validate WhatWeb options."""

        super().validate_options()

        aggression = self.get_option(
            "aggression",
            1,
        )

        if (
            not isinstance(aggression, int)
            or isinstance(aggression, bool)
        ):
            raise TypeError(
                "WhatWeb aggression must be an integer."
            )

        if aggression < 1 or aggression > 4:
            raise ValueError(
                "WhatWeb aggression must be between 1 and 4."
            )

    def build_arguments(self) -> list[str]:
        """Build WhatWeb-specific command-line arguments."""

        self.validate_options()

        return [
            "-a",
            str(
                self.get_option(
                    "aggression",
                    1,
                )
            ),
            self.context.target,
        ]


###############################################################################
# KITERUNNER
###############################################################################


class KiterunnerTool(
    ToolAdapter
):
    """
    API-aware route discovery using Kiterunner.

    ScopeForgeX uses a local KiteBuilder route corpus so execution does not
    depend on Kiterunner's remote Assetnote wordlist service.

    Full-scan mode is enabled by default because the normal Kiterunner
    two-phase workflow can prompt interactively when the preflight phase
    produces no results. ScopeForgeX workflows must remain non-interactive.
    """

    definition = ToolDefinition(
        name="kiterunner",
        capability="api_route_discovery",
        phase="enumeration",
        purpose=(
            "Discover API routes using Kiterunner's API-aware route corpus."
        ),
        executable="kr",
        input_type="url",
        output_type="raw",
        finding_types=(
            "API_ENDPOINT",
            "API_ROUTE",
        ),
        dependencies=(
            "kiterunner",
        ),
        options=(
            ToolOption(
                name="wordlist",
                flag="-w",
                description=(
                    "Local Kiterunner KiteBuilder route corpus."
                ),
                option_type="path",
                default=(
                    "/home/kali/tools/kiterunner/"
                    "wordlists/routes-small.kite"
                ),
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="threads",
                flag="-x",
                description=(
                    "Maximum concurrent connections per host."
                ),
                option_type="integer",
                default=10,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="full_scan",
                flag="--kitebuilder-full-scan",
                description=(
                    "Run the complete KiteBuilder corpus without "
                    "interactive two-phase continuation."
                ),
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="quiet",
                flag="-q",
                description=(
                    "Suppress unnecessary Kiterunner terminal output."
                ),
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(
        self,
    ) -> None:
        """Validate Kiterunner options."""

        super().validate_options()

        wordlist = self.get_option(
            "wordlist",
            (
                "/home/kali/tools/kiterunner/"
                "wordlists/routes-small.kite"
            ),
        )

        if wordlist is not None:
            path = Path(
                str(wordlist)
            ).expanduser()

            if not path.is_file():
                raise ValueError(
                    f"Kiterunner wordlist not found: {path}"
                )

        threads = self.get_option(
            "threads",
            10,
        )

        if (
            not isinstance(
                threads,
                int,
            )
            or isinstance(
                threads,
                bool,
            )
        ):
            raise TypeError(
                "Kiterunner threads must be an integer."
            )

        if threads <= 0:
            raise ValueError(
                "Kiterunner threads must be greater than zero."
            )

        for name in (
            "full_scan",
            "quiet",
        ):
            value = self.get_option(
                name,
                True,
            )

            if not isinstance(
                value,
                bool,
            ):
                raise TypeError(
                    f"Kiterunner {name} must be boolean."
                )

    def build_arguments(
        self,
    ) -> list[str]:
        """Build Kiterunner-specific command-line arguments."""

        self.validate_options()

        wordlist = self.get_option(
            "wordlist",
            (
                "/home/kali/tools/kiterunner/"
                "wordlists/routes-small.kite"
            ),
        )

        arguments = [
            "scan",
            self.context.target,
            "-w",
            str(wordlist),
        ]

        threads = self.get_option(
            "threads",
            10,
        )

        arguments.extend(
            [
                "-x",
                str(threads),
            ]
        )

        if self.get_option(
            "full_scan",
            True,
        ):
            arguments.append(
                "--kitebuilder-full-scan"
            )

        if self.get_option(
            "quiet",
            True,
        ):
            arguments.append(
                "-q"
            )

        return arguments


###############################################################################
# JSLUICE
###############################################################################


def _normalize_javascript_http_target(
    target: str,
) -> str:
    """
    Normalize a workflow target into an HTTP(S) URL.

    JSLuice treats a bare hostname as a local filename. ScopeForgeX uses an
    HTTPS URL for bare web targets so JSLuice receives an HTTP-based input.
    """

    value = str(
        target
    ).strip()

    if not value:
        raise ValueError(
            "JSLuice requires a JavaScript target."
        )

    lowered = value.lower()

    if lowered.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return value

    return (
        "https://"
        + value
    )


def _javascript_targets_from_context(
    context: ToolContext,
) -> list[str]:
    """
    Resolve JSLuice inputs from ToolContext.

    Explicit input_data takes precedence over the primary workflow target.
    When input_data is empty, the primary target is normalized to an HTTP(S)
    URL rather than being passed as a local filename.
    """

    values = [
        str(value).strip()
        for value in context.input_data
        if value is not None
        and str(value).strip()
    ]

    if values:
        return sorted(
            set(
                values
            )
        )

    return [
        _normalize_javascript_http_target(
            context.target
        )
    ]


class JSLuiceTool(
    ToolAdapter
):
    """
    Analyze JavaScript resources for URLs, API references and secrets.

    JSLuice URL mode accepts local files and HTTP-based inputs. ScopeForgeX
    normalizes bare workflow hostnames into HTTP(S) inputs when no explicit
    JavaScript inputs are available.
    """

    definition = ToolDefinition(
        name="jsluice",
        capability="javascript_attack_surface_analysis",
        phase="enumeration",
        purpose=(
            "Extract endpoints, API references and secret candidates from "
            "JavaScript resources."
        ),
        executable="jsluice",
        input_type="url",
        output_type="raw",
        finding_types=(
            "JS_ENDPOINT",
            "JS_URL",
            "SECRET_CANDIDATE",
            "API_REFERENCE",
        ),
        dependencies=(
            "jsluice",
        ),
        options=(
            ToolOption(
                name="concurrency",
                flag="-c",
                description="Concurrent JSLuice workers.",
                option_type="integer",
                default=1,
                safe=True,
                aggressive=True,
            ),
            ToolOption(
                name="include_source",
                flag="-S",
                description="Include source references.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="ignore_strings",
                flag="-I",
                description="Ignore string literals.",
                option_type="boolean",
                default=False,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="secrets",
                flag="secrets",
                description="Run JSLuice secret extraction.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
            ToolOption(
                name="resolve_paths",
                flag="-R",
                description="Resolve relative paths.",
                option_type="boolean",
                default=True,
                safe=True,
                aggressive=False,
            ),
        ),
        safe=True,
        aggressive=True,
    )

    def validate_options(self) -> None:
        """Validate JSLuice options."""

        super().validate_options()

        concurrency = self.get_option(
            "concurrency",
            1,
        )

        if (
            not isinstance(
                concurrency,
                int,
            )
            or isinstance(
                concurrency,
                bool,
            )
        ):
            raise TypeError(
                "JSLuice concurrency must be an integer."
            )

        if concurrency <= 0:
            raise ValueError(
                "JSLuice concurrency must be greater than zero."
            )

        for name in (
            "include_source",
            "ignore_strings",
            "secrets",
            "resolve_paths",
        ):
            value = self.get_option(
                name,
                False,
            )

            if not isinstance(
                value,
                bool,
            ):
                raise TypeError(
                    f"JSLuice {name} must be boolean."
                )

    def build_arguments(self) -> list[str]:
        """
        Build the JSLuice URLs command.

        Explicit JavaScript inputs are preferred. Otherwise the workflow target
        is normalized to an HTTP(S) URL.
        """

        self.validate_options()

        targets = _javascript_targets_from_context(
            self.context
        )

        if not targets:
            raise ValueError(
                "JSLuice requires at least one JavaScript input."
            )

        arguments = [
            "urls",
            "-c",
            str(
                self.get_option(
                    "concurrency",
                    1,
                )
            ),
        ]

        if self.get_option(
            "include_source",
            True,
        ):
            arguments.append(
                "-S"
            )

        if self.get_option(
            "ignore_strings",
            False,
        ):
            arguments.append(
                "-I"
            )

        if self.get_option(
            "resolve_paths",
            True,
        ):
            arguments.extend(
                [
                    "-R",
                    targets[0],
                ]
            )

        arguments.extend(
            targets
        )

        return arguments

    def build_secrets_arguments(self) -> list[str]:
        """Build the JSLuice secrets-analysis command."""

        self.validate_options()

        targets = _javascript_targets_from_context(
            self.context
        )

        if not targets:
            raise ValueError(
                "JSLuice requires at least one JavaScript input."
            )

        arguments = [
            "secrets",
            "-c",
            str(
                self.get_option(
                    "concurrency",
                    1,
                )
            ),
        ]

        arguments.extend(
            targets
        )

        return arguments


###############################################################################
# Stage 2 Tool Collection
###############################################################################


ALL_STAGE2_WEB_ENUM_TOOLS = [
    HttpxTool,
    KatanaTool,
    FfufTool,
    WhatWebTool,
    KiterunnerTool,
    JSLuiceTool,
]


###############################################################################
# Compatibility Alias
###############################################################################


# Compatibility alias retained for code that uses the previous class spelling.
FFUFTool = FfufTool


###############################################################################
# Public API
###############################################################################


__all__ = [
    "HttpxTool",
    "KatanaTool",
    "KiterunnerTool",
    "JSLuiceTool",
    "WhatWebTool",
    "FfufTool",
    "FFUFTool",
    "ALL_STAGE2_WEB_ENUM_TOOLS",
]
