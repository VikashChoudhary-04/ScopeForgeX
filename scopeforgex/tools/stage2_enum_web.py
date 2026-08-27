"""
ScopeForgeX
Stage 2 — Web Enumeration Compatibility Tools
==============================================

Provides the legacy Stage 2 web-enumeration tools:

- HTTPX
- Katana
- WhatWeb
- WAFW00F
- FFUF

The module uses the canonical ExecutionResult model and remains compatible
with the ScopeForgeX tool registry.

v1.1.0
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import questionary

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log
from scopeforgex.wordlists import (
    find_default_web_fuzz_wordlist,
    is_valid_wordlist,
)


###############################################################################
# Helper Functions
###############################################################################


def _enum_directory(
    ctx: dict,
) -> Path:
    """
    Return the Stage 2 enumeration directory.
    """

    directory = (
        Path(ctx["outdir"])
        / "enum"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _safe_exists(
    path: Path,
) -> bool:
    """
    Return True when a path exists and contains data.
    """

    return (
        path.exists()
        and path.stat().st_size > 0
    )


def _quote(
    value: str,
) -> str:
    """
    Shell-safe quoting.
    """

    return shlex.quote(
        value
    )


def _normalize_target(
    target: str,
) -> str:
    """
    Ensure targets contain a URL scheme.
    """

    target = target.strip()

    if target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return target

    return f"https://{target}"


def _load_pipeline_targets(
    ctx: dict,
) -> list[str]:
    """
    Determine web enumeration targets.

    Priority:

    1. Stage 1 hosts_final
    2. Root target
    """

    pipeline = ctx.get(
        "pipeline",
        {},
    )

    hosts_file = pipeline.get(
        "hosts_final"
    )

    targets: list[str] = []

    if hosts_file and os.path.exists(
        hosts_file
    ):
        with open(
            hosts_file,
            encoding="utf-8",
        ) as handle:

            for line in handle:
                host = line.strip()

                if host:
                    targets.append(
                        _normalize_target(
                            host
                        )
                    )

    if not targets:
        targets.append(
            _normalize_target(
                ctx["target"]
            )
        )

    return sorted(
        set(targets)
    )


def _build_notes(
    logfile: Path,
    message: str,
) -> str:
    """
    Build consistent execution notes from a log file.
    """

    notes = build_notes_from_log(
        str(logfile),
        message,
    )

    if not _safe_exists(
        logfile
    ):
        notes += (
            " [Log file missing.]"
        )

    return notes


def _missing_tool(
    name: str,
    capability: str,
) -> ExecutionResult:
    """
    Return a canonical failure result for a missing executable.
    """

    return ExecutionResult.failure(
        tool=name,
        capability=capability,
        error=f"{name} not installed",
    )


###############################################################################
# Base Class
###############################################################################


class WebEnumerationTool(
    ToolBase
):
    """
    Shared functionality for legacy Stage 2 web-enumeration tools.
    """

    risk = "low"
    stage = 2

    def enum_dir(
        self,
        ctx: dict,
    ) -> Path:
        """
        Return the Stage 2 enumeration directory.
        """

        return _enum_directory(
            ctx
        )

    def output_file(
        self,
        ctx: dict,
        filename: str,
    ) -> Path:
        """
        Return a file inside the Stage 2 enumeration directory.
        """

        return (
            self.enum_dir(
                ctx
            )
            / filename
        )

    def targets(
        self,
        ctx: dict,
    ) -> list[str]:
        """
        Return the targets selected for web enumeration.
        """

        return _load_pipeline_targets(
            ctx
        )

    def verify_output(
        self,
        output: Path,
        notes: str,
        warning: str,
    ) -> str:
        """
        Append a warning when the expected output is empty or missing.
        """

        if not _safe_exists(
            output
        ):
            notes += (
                f" [{warning}]"
            )

        return notes


###############################################################################
# HTTPX
###############################################################################


class HttpxTool(
    WebEnumerationTool
):
    """
    HTTP service probing using HTTPX.
    """

    name = "httpx"
    description = (
        "Identify reachable HTTP services and collect web service metadata"
    )
    capability = "http_service_probing"
    output_type = "http_services"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute HTTPX against the selected targets.
        """

        if not is_tool_installed(
            "httpx"
        ):
            return _missing_tool(
                self.name,
                self.capability,
            )

        output = self.output_file(
            ctx,
            "httpx.txt",
        )

        logfile = self.output_file(
            ctx,
            "httpx.log",
        )

        targets_file = self.output_file(
            ctx,
            "httpx_targets.txt",
        )

        targets = self.targets(
            ctx
        )

        targets_file.write_text(
            "\n".join(targets) + "\n",
            encoding="utf-8",
        )

        command = (
            "httpx "
            f"-l {_quote(str(targets_file))} "
            "-silent "
            "-status-code "
            "-title "
            "-server "
            "-tech-detect "
            f"-o {_quote(str(output))}"
        )

        execution = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(logfile),
            timeout=600,
        )

        notes = _build_notes(
            logfile,
            "HTTPX completed.",
        )

        if not execution.success:
            result = ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="HTTPX execution failed.",
            )

            for artifact in (
                targets_file,
                output,
                logfile,
            ):
                result.add_artifact(
                    artifact
                )

            result.metadata.update(
                {
                    "targets": len(targets),
                }
            )

            return result

        if not _safe_exists(
            output
        ):
            notes += (
                " [No HTTP services detected.]"
            )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
            artifacts=[
                str(targets_file),
                str(output),
                str(logfile),
            ],
            metadata={
                "notes": notes,
                "targets": len(targets),
            },
        )


###############################################################################
# KATANA
###############################################################################


class KatanaTool(
    WebEnumerationTool
):
    """
    Web crawling and endpoint discovery using Katana.
    """

    name = "katana"
    description = (
        "Web crawling and application endpoint discovery"
    )
    capability = "web_crawling"
    output_type = "web_crawl"
    risk = "medium"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute Katana against the selected targets.
        """

        if not is_tool_installed(
            "katana"
        ):
            return _missing_tool(
                self.name,
                self.capability,
            )

        output = self.output_file(
            ctx,
            "katana.txt",
        )

        logfile = self.output_file(
            ctx,
            "katana.log",
        )

        targets_file = self.output_file(
            ctx,
            "katana_targets.txt",
        )

        targets = self.targets(
            ctx
        )

        targets_file.write_text(
            "\n".join(targets) + "\n",
            encoding="utf-8",
        )

        command = (
            "katana "
            f"-list {_quote(str(targets_file))} "
            "-silent "
            f"-o {_quote(str(output))}"
        )

        execution = run_command(
            tool=self.name,
            capability=self.capability,
            cmd=command,
            outfile=str(logfile),
            timeout=600,
        )

        notes = _build_notes(
            logfile,
            "Katana completed.",
        )

        if not execution.success:
            result = ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error="Katana execution failed.",
            )

            for artifact in (
                targets_file,
                output,
                logfile,
            ):
                result.add_artifact(
                    artifact
                )

            result.metadata.update(
                {
                    "targets": len(targets),
                }
            )

            return result

        if not _safe_exists(
            output
        ):
            notes += (
                " [No endpoints discovered.]"
            )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
            artifacts=[
                str(targets_file),
                str(output),
                str(logfile),
            ],
            metadata={
                "notes": notes,
                "targets": len(targets),
            },
        )


###############################################################################
# WhatWeb
###############################################################################


class WhatWebTool(
    WebEnumerationTool
):
    """
    Website technology fingerprinting.
    """

    name = "whatweb"
    description = "Website fingerprinting"
    capability = "technology_fingerprinting"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute WhatWeb against the selected targets.
        """

        if not is_tool_installed(
            "whatweb"
        ):
            return _missing_tool(
                self.name,
                self.capability,
            )

        output = self.output_file(
            ctx,
            "whatweb.txt",
        )

        logfile = self.output_file(
            ctx,
            "whatweb.log",
        )

        targets = self.targets(
            ctx
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as report:

            for target in targets:

                command = (
                    "whatweb "
                    f"{_quote(target)}"
                )

                run_command(
                    tool=self.name,
                    capability=self.capability,
                    cmd=command,
                    outfile=str(
                        logfile
                    ),
                )

                report.write(
                    f"{target}\n"
                )

        notes = _build_notes(
            logfile,
            "WhatWeb completed.",
        )

        notes = self.verify_output(
            output,
            notes,
            "No fingerprint data generated.",
        )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
            artifacts=[
                str(output),
                str(logfile),
            ],
            metadata={
                "notes": notes,
                "targets": len(
                    targets
                ),
            },
        )


###############################################################################
# WAFW00F
###############################################################################


class Wafw00fTool(
    WebEnumerationTool
):
    """
    Web Application Firewall detection.
    """

    name = "wafw00f"
    description = (
        "Detect Web Application Firewalls"
    )
    capability = "waf_detection"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute WAFW00F against the selected targets.
        """

        if not is_tool_installed(
            "wafw00f"
        ):
            return _missing_tool(
                self.name,
                self.capability,
            )

        output = self.output_file(
            ctx,
            "wafw00f.txt",
        )

        logfile = self.output_file(
            ctx,
            "wafw00f.log",
        )

        targets = self.targets(
            ctx
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as report:

            for target in targets:

                command = (
                    "wafw00f "
                    f"{_quote(target)}"
                )

                run_command(
                    tool=self.name,
                    capability=self.capability,
                    cmd=command,
                    outfile=str(
                        logfile
                    ),
                )

                report.write(
                    f"{target}\n"
                )

        notes = _build_notes(
            logfile,
            "WAF detection completed.",
        )

        notes = self.verify_output(
            output,
            notes,
            "No WAF information collected.",
        )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
            artifacts=[
                str(output),
                str(logfile),
            ],
            metadata={
                "notes": notes,
                "targets": len(
                    targets
                ),
            },
        )


###############################################################################
# FFUF Helpers
###############################################################################


def _select_wordlist() -> str | None:
    """
    Interactively select an FFUF wordlist.

    Returns:
        Valid wordlist path or None.
    """

    mode = questionary.select(
        "Choose FFUF wordlist:",
        choices=[
            "Auto-detect default",
            "Specify custom path",
        ],
    ).ask()

    if mode == (
        "Auto-detect default"
    ):
        wordlist = (
            find_default_web_fuzz_wordlist()
        )

        if not wordlist:
            wordlist = questionary.text(
                "Default wordlist not found. Enter path:"
            ).ask()

    else:
        wordlist = questionary.text(
            "Enter wordlist path:"
        ).ask()

    if not wordlist:
        return None

    if not is_valid_wordlist(
        wordlist
    ):
        return None

    return wordlist


###############################################################################
# FFUF
###############################################################################


class FFUFTool(
    WebEnumerationTool
):
    """
    Directory and content discovery using FFUF.
    """

    name = "ffuf"
    description = (
        "Directory and content discovery"
    )
    capability = "content_discovery"
    risk = "medium"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute FFUF against the selected targets.
        """

        if not is_tool_installed(
            "ffuf"
        ):
            return _missing_tool(
                self.name,
                self.capability,
            )

        confirmed = questionary.confirm(
            "Run FFUF directory enumeration?"
        ).ask()

        if not confirmed:
            return ExecutionResult.skipped(
                tool=self.name,
                capability=self.capability,
                reason="Skipped by user",
            )

        wordlist = _select_wordlist()

        if not wordlist:
            return ExecutionResult.failure(
                tool=self.name,
                capability=self.capability,
                error=(
                    "Invalid wordlist selected."
                ),
            )

        enum_dir = self.enum_dir(
            ctx
        )

        logfile = (
            enum_dir
            / "ffuf.log"
        )

        summary = (
            enum_dir
            / "ffuf.md"
        )

        wordlist_file = (
            enum_dir
            / "wordlist_used.txt"
        )

        wordlist_file.write_text(
            wordlist + "\n",
            encoding="utf-8",
        )

        generated_outputs = [
            summary,
            logfile,
            wordlist_file,
        ]

        targets = self.targets(
            ctx
        )

        with summary.open(
            "w",
            encoding="utf-8",
        ) as report:

            report.write(
                "# FFUF Enumeration Results\n\n"
            )

            report.write(
                f"Wordlist: `{wordlist}`\n\n"
            )

            for index, target in enumerate(
                targets,
                start=1,
            ):
                report.write(
                    f"## Target {index}\n\n"
                )

                report.write(
                    f"{target}\n\n"
                )

                outfile = (
                    enum_dir
                    / (
                        f"ffuf_target_{index}.md"
                    )
                )

                command = (
                    "ffuf "
                    f"-u {_quote(target)}/FUZZ "
                    f"-w {_quote(wordlist)} "
                    "-mc all "
                    "-of md "
                    f"-o {_quote(str(outfile))}"
                )

                run_command(
                    tool=self.name,
                    capability=self.capability,
                    cmd=command,
                    outfile=str(
                        logfile
                    ),
                )

                if _safe_exists(
                    outfile
                ):
                    generated_outputs.append(
                        outfile
                    )

                    report.write(
                        "Output: "
                        f"`{outfile.name}`\n\n"
                    )

                else:
                    report.write(
                        "No results generated.\n\n"
                    )

        notes = _build_notes(
            logfile,
            "FFUF completed.",
        )

        notes = self.verify_output(
            summary,
            notes,
            "No FFUF results produced.",
        )

        return ExecutionResult.success_result(
            tool=self.name,
            capability=self.capability,
            artifacts=[
                str(path)
                for path in generated_outputs
            ],
            metadata={
                "notes": notes,
                "targets": len(
                    targets
                ),
                "wordlist": wordlist,
            },
        )


###############################################################################
# Tool Registration
###############################################################################


ALL_STAGE2_WEB_ENUM_TOOLS = [
    WhatWebTool(),
    Wafw00fTool(),
    FFUFTool(),
]


###############################################################################
# Module Exports
###############################################################################


__all__ = [
    "WebEnumerationTool",
    "HttpxTool",
    "KatanaTool",
    "WhatWebTool",
    "Wafw00fTool",
    "FFUFTool",
    "ALL_STAGE2_WEB_ENUM_TOOLS",
]

