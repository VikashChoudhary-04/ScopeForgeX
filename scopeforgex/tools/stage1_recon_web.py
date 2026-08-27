"""
ScopeForgeX Web Reconnaissance Tools
====================================

Capability-oriented web reconnaissance adapters.

Integrated capabilities:
    - Active subdomain discovery
    - HTTP service probing
    - Web crawling and endpoint discovery

Architecture
------------
Tool adapters own:

    - tool metadata
    - option handling
    - command construction
    - execution delegation
    - artifact collection

The workflow engine must not construct tool-specific commands.

Assessment-phase classification is owned by the canonical tool registry.
Legacy ``stage`` metadata is intentionally not used.

v1.2.0
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.validators import looks_like_hostname
from scopeforgex.wordlists import (
    find_default_subdomain_wordlist,
)


###############################################################################
# Helpers
###############################################################################


def _recon_dir(ctx: dict[str, Any]) -> Path:
    """
    Return the reconnaissance output directory.
    """

    directory = Path(ctx["outdir"]) / "recon"

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _quote(value: str) -> str:
    """
    Safely quote a shell argument.
    """

    return shlex.quote(value)


def _empty_file(path: str | Path) -> None:
    """
    Create or truncate a file.
    """

    output = Path(path)

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        "",
        encoding="utf-8",
    )


def _dedupe_file(path: str | Path) -> int:
    """
    Remove duplicate non-empty lines while preserving order.

    Returns:
        Number of unique entries.
    """

    output = Path(path)

    if not output.exists():
        return 0

    try:
        with output.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as infile:

            lines = [
                line.strip()
                for line in infile
                if line.strip()
            ]

        unique = list(
            dict.fromkeys(lines)
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as outfile:

            if unique:
                outfile.write(
                    "\n".join(unique)
                    + "\n"
                )

    except OSError:
        return 0

    return len(unique)


def _append_clean_hosts(
    input_path: str | Path,
    output_path: str | Path,
) -> None:
    """
    Append valid hostnames from input_path into output_path.
    """

    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        return

    try:
        with input_file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as infile:

            hosts = [
                line.strip().lower()
                for line in infile
                if looks_like_hostname(
                    line.strip()
                )
            ]

    except OSError:
        return

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as outfile:

        for host in hosts:
            outfile.write(
                host + "\n"
            )


def _append_clean_urls(
    input_path: str | Path,
    output_path: str | Path,
) -> None:
    """
    Append HTTP/HTTPS URLs from input_path into output_path.
    """

    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        return

    try:
        with input_file.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as infile:

            urls = [
                line.strip()
                for line in infile
                if line.strip().startswith(
                    (
                        "http://",
                        "https://",
                    )
                )
            ]

    except OSError:
        return

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_file.open(
        "a",
        encoding="utf-8",
    ) as outfile:

        for url in urls:
            outfile.write(
                url + "\n"
            )


def _tool_missing(
    tool_name: str,
    capability: str,
) -> ExecutionResult | None:
    """
    Return a failure result when an executable is unavailable.
    """

    if is_tool_installed(tool_name):
        return None

    return ExecutionResult.failure(
        tool=tool_name,
        capability=capability,
        error=f"{tool_name} not installed",
    )


###############################################################################
# Subhunt
###############################################################################


class SubhuntTool(ToolBase):
    """
    Perform active wordlist-based subdomain discovery with Subhunt.
    """

    name = "subhunt"
    display_name = "Subhunt"

    description = (
        "Active wordlist-based subdomain discovery."
    )

    capability = (
        "active_subdomain_discovery"
    )

    input_type = "domain"
    output_type = "discovery"

    finding_types = (
        "SUBDOMAIN",
    )

    risk = "low"

    supported_options = (
        "wordlist",
        "threads",
        "quiet",
    )

    default_options = {
        "wordlist": None,
        "threads": 50,
        "quiet": True,
    }

    def _resolve_options(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Resolve Subhunt options from the execution context.
        """

        configured = ctx.get(
            "tool_options",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        tool_options = configured.get(
            self.name,
            {},
        )

        if not isinstance(
            tool_options,
            dict,
        ):
            tool_options = {}

        return self.validate_options(
            tool_options
        )

    def _resolve_wordlist(
        self,
        options: dict[str, Any],
    ) -> str | None:
        """
        Resolve the configured or default Subhunt wordlist.
        """

        configured = options.get(
            "wordlist"
        )

        if configured:
            return str(
                configured
            )

        return find_default_subdomain_wordlist()

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the Subhunt command.
        """

        options = self._resolve_options(
            ctx
        )

        target = str(
            ctx.get(
                "target",
                "",
            )
        ).strip()

        if not target:
            raise ValueError(
                "Subhunt requires a target domain."
            )

        command = [
            "subhunt",
            "-d",
            target,
        ]

        wordlist = self._resolve_wordlist(
            options
        )

        if wordlist:
            command.extend(
                [
                    "--bruteforce",
                    wordlist,
                ]
            )

        threads = options.get(
            "threads"
        )

        if threads is not None:
            command.extend(
                [
                    "--threads",
                    str(threads),
                ]
            )

        if options.get(
            "quiet",
            False,
        ):
            command.append(
                "--quiet"
            )

        return " ".join(
            _quote(part)
            for part in command
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute Subhunt active subdomain discovery.
        """

        capability = self.capability

        if ctx.get(
            "target_type"
        ) != "web":

            return ExecutionResult.skipped(
                tool=self.name,
                capability=capability,
                reason="Skipped (not web target)",
            )

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

        recon_dir = _recon_dir(
            ctx
        )

        output = (
            recon_dir
            / "subhunt.txt"
        )

        log = (
            recon_dir
            / "subhunt.log"
        )

        _empty_file(
            output
        )

        try:
            command = self.build_command(
                ctx
            )
        except ValueError as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=(
                f"{command} "
                f"> {_quote(str(output))}"
            ),
            outfile=str(log),
            timeout=600,
        )

        result.add_artifact(
            output
        )

        result.add_artifact(
            log
        )

        count = _dedupe_file(
            output
        )

        result.metadata.update(
            {
                "subdomains": count,
                "output_file": str(output),
            }
        )

        return result


###############################################################################
# HTTPX
###############################################################################


class HttpxTool(ToolBase):
    """
    Probe hosts for reachable HTTP services.
    """

    name = "httpx"
    display_name = "httpx"

    description = (
        "Identify reachable HTTP services and collect HTTP status, "
        "title, server and technology metadata."
    )

    capability = (
        "http_service_probing"
    )

    input_type = "host_list"
    output_type = "http_services"

    finding_types = (
        "HTTP_SERVICE",
        "HTTP_STATUS",
        "WEB_SERVER",
    )

    risk = "low"

    supported_options = (
        "ports",
        "status_code",
        "title",
        "server",
        "technology",
    )

    default_options = {
        "status_code": True,
        "title": True,
        "server": True,
        "technology": True,
    }

    def _resolve_options(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        configured = ctx.get(
            "tool_options",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        options = configured.get(
            self.name,
            {},
        )

        if not isinstance(
            options,
            dict,
        ):
            options = {}

        return self.validate_options(
            options
        )

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the httpx command from structured options.
        """

        input_file = ctx.get(
            "input_file"
        )

        if not input_file:
            raise ValueError(
                "httpx requires an input_file."
            )

        options = self._resolve_options(
            ctx
        )

        command = [
            "httpx",
            "-l",
            str(input_file),
            "-silent",
        ]

        ports = options.get(
            "ports"
        )

        if ports:
            command.extend(
                [
                    "-ports",
                    str(ports),
                ]
            )

        if options.get(
            "status_code",
            False,
        ):
            command.append(
                "-status-code"
            )

        if options.get(
            "title",
            False,
        ):
            command.append(
                "-title"
            )

        if options.get(
            "server",
            False,
        ):
            command.append(
                "-server"
            )

        if options.get(
            "technology",
            False,
        ):
            command.append(
                "-tech-detect"
            )

        return " ".join(
            _quote(part)
            for part in command
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute httpx against a host list.
        """

        capability = self.capability

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

        input_file = ctx.get(
            "input_file"
        )

        if not input_file:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error="httpx input_file is missing.",
            )

        input_path = Path(
            input_file
        )

        if not input_path.exists():
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=(
                    f"httpx input file does not exist: "
                    f"{input_path}"
                ),
            )

        recon_dir = _recon_dir(
            ctx
        )

        output = (
            recon_dir
            / "httpx.txt"
        )

        log = (
            recon_dir
            / "httpx.log"
        )

        _empty_file(
            output
        )

        local_ctx = dict(
            ctx
        )

        local_ctx["input_file"] = str(
            input_path
        )

        try:
            command = self.build_command(
                local_ctx
            )
        except ValueError as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=(
                f"{command} "
                f"-o {_quote(str(output))}"
            ),
            outfile=str(log),
            timeout=600,
        )

        result.add_artifact(
            input_path
        )

        result.add_artifact(
            output
        )

        result.add_artifact(
            log
        )

        services = _dedupe_file(
            output
        )

        result.metadata.update(
            {
                "input_file": str(input_path),
                "output_file": str(output),
                "http_services": services,
            }
        )

        return result


###############################################################################
# Katana
###############################################################################


class KatanaTool(ToolBase):
    """
    Crawl reachable web services and discover URLs/endpoints.
    """

    name = "katana"
    display_name = "Katana"

    description = (
        "Web crawling and application endpoint discovery."
    )

    capability = (
        "web_crawling"
    )

    input_type = "url_list"
    output_type = "web_crawl"

    finding_types = (
        "URL",
        "ENDPOINT",
        "PARAMETER",
        "FORM",
        "RESOURCE",
    )

    risk = "medium"

    supported_options = (
        "depth",
        "concurrency",
        "rate_limit",
        "headless",
    )

    default_options = {
        "depth": 3,
    }

    def _resolve_options(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        configured = ctx.get(
            "tool_options",
            {},
        )

        if not isinstance(
            configured,
            dict,
        ):
            configured = {}

        options = configured.get(
            self.name,
            {},
        )

        if not isinstance(
            options,
            dict,
        ):
            options = {}

        return self.validate_options(
            options
        )

    def build_command(
        self,
        ctx: dict[str, Any],
    ) -> str:
        """
        Build the Katana crawling command.
        """

        input_file = ctx.get(
            "input_file"
        )

        if not input_file:
            raise ValueError(
                "Katana requires an input_file."
            )

        options = self._resolve_options(
            ctx
        )

        command = [
            "katana",
            "-list",
            str(input_file),
            "-silent",
        ]

        depth = options.get(
            "depth"
        )

        if depth is not None:
            command.extend(
                [
                    "-depth",
                    str(depth),
                ]
            )

        concurrency = options.get(
            "concurrency"
        )

        if concurrency is not None:
            command.extend(
                [
                    "-c",
                    str(concurrency),
                ]
            )

        rate_limit = options.get(
            "rate_limit"
        )

        if rate_limit is not None:
            command.extend(
                [
                    "-rl",
                    str(rate_limit),
                ]
            )

        if options.get(
            "headless",
            False,
        ):
            command.append(
                "-headless"
            )

        return " ".join(
            _quote(part)
            for part in command
        )

    def run(
        self,
        ctx: dict[str, Any],
    ) -> ExecutionResult:
        """
        Execute Katana crawling.
        """

        capability = self.capability

        missing = _tool_missing(
            self.name,
            capability,
        )

        if missing:
            return missing

        input_file = ctx.get(
            "input_file"
        )

        if not input_file:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error="Katana input_file is missing.",
            )

        input_path = Path(
            input_file
        )

        if not input_path.exists():
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=(
                    f"Katana input file does not exist: "
                    f"{input_path}"
                ),
            )

        recon_dir = _recon_dir(
            ctx
        )

        output = (
            recon_dir
            / "katana.txt"
        )

        log = (
            recon_dir
            / "katana.log"
        )

        _empty_file(
            output
        )

        local_ctx = dict(
            ctx
        )

        local_ctx["input_file"] = str(
            input_path
        )

        try:
            command = self.build_command(
                local_ctx
            )
        except ValueError as exc:
            return ExecutionResult.failure(
                tool=self.name,
                capability=capability,
                error=str(exc),
            )

        result = run_command(
            tool=self.name,
            capability=capability,
            cmd=(
                f"{command} "
                f"-o {_quote(str(output))}"
            ),
            outfile=str(log),
            timeout=600,
        )

        result.add_artifact(
            input_path
        )

        result.add_artifact(
            output
        )

        result.add_artifact(
            log
        )

        urls = _dedupe_file(
            output
        )

        result.metadata.update(
            {
                "input_file": str(input_path),
                "output_file": str(output),
                "urls": urls,
            }
        )

        return result


###############################################################################
# Public API
###############################################################################


ALL_STAGE1_WEB_TOOLS = [
    SubhuntTool(),
    HttpxTool(),
    KatanaTool(),
]


__all__ = [
    "SubhuntTool",
    "HttpxTool",
    "KatanaTool",
    "ALL_STAGE1_WEB_TOOLS",
]
