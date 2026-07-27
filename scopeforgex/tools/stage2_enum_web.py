"""
ScopeForgeX v0.4.0
Stage 2 - Web Enumeration

Features
--------
* Shared helper utilities
* Multiple target support
* Better logging
* Consistent ToolResult handling
* Automatic output validation
* Cleaner architecture
* Easier future tool integration
"""

from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Iterable

import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log
from scopeforgex.wordlists import (
    find_default_web_fuzz_wordlist,
    is_valid_wordlist,
)

###############################################################################
# Helper Functions
###############################################################################


def _enum_directory(ctx: dict) -> Path:
    """
    Return Stage-2 enum directory.

    Creates it automatically if required.
    """

    directory = Path(ctx["outdir"]) / "enum"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _safe_exists(path: Path) -> bool:
    """
    True if file exists and contains data.
    """

    return path.exists() and path.stat().st_size > 0


def _quote(value: str) -> str:
    """
    Shell-safe quoting.
    """

    return shlex.quote(value)


def _normalize_target(target: str) -> str:
    """
    Ensure targets always contain a scheme.
    """

    target = target.strip()

    if target.startswith(("http://", "https://")):
        return target

    return f"https://{target}"


def _load_pipeline_targets(ctx: dict) -> list[str]:
    """
    Determine web enumeration targets.

    Priority

    1. hosts_final.txt
    2. root target
    """

    pipeline = ctx.get("pipeline", {})

    hosts_file = pipeline.get("hosts_final")

    targets: list[str] = []

    if hosts_file and os.path.exists(hosts_file):

        with open(
            hosts_file,
            encoding="utf-8",
        ) as handle:

            for line in handle:
                host = line.strip()

                if host:
                    targets.append(
                        _normalize_target(host)
                    )

    if not targets:
        targets.append(
            _normalize_target(ctx["target"])
        )

    return sorted(set(targets))


def _build_notes(logfile: Path, message: str) -> str:
    """
    Consistent report note generation.
    """

    notes = build_notes_from_log(
        str(logfile),
        message,
    )

    if not _safe_exists(logfile):
        notes += " [Log file missing.]"

    return notes


def _missing_tool(name: str) -> ToolResult:
    return ToolResult(
        name,
        False,
        [],
        f"{name} not installed",
    )


###############################################################################
# Base Class
###############################################################################


class WebEnumerationTool(ToolBase):
    """
    Shared helper methods for all Stage-2 tools.
    """

    risk = "low"
    stage = 2

    def enum_dir(self, ctx: dict) -> Path:
        return _enum_directory(ctx)

    def output_file(
        self,
        ctx: dict,
        filename: str,
    ) -> Path:
        return self.enum_dir(ctx) / filename

    def targets(
        self,
        ctx: dict,
    ) -> list[str]:
        return _load_pipeline_targets(ctx)

    def verify_output(
        self,
        output: Path,
        notes: str,
        warning: str,
    ) -> str:

        if not _safe_exists(output):
            notes += f" [{warning}]"

        return notes


###############################################################################
# WhatWeb
###############################################################################


class WhatWebTool(WebEnumerationTool):

    name = "whatweb"
    description = "Website fingerprinting"

    def run(
        self,
        ctx: dict,
    ) -> ToolResult:

        if not is_tool_installed("whatweb"):
            return _missing_tool(self.name)

        output = self.output_file(
            ctx,
            "whatweb.txt",
        )

        logfile = self.output_file(
            ctx,
            "whatweb.log",
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as report:

            for target in self.targets(ctx):

                command = (
                    f"whatweb {_quote(target)}"
                )

                run_cmd(
                    command,
                    outfile=str(logfile),
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

        return ToolResult(
            self.name,
            True,
            [
                str(output),
                str(logfile),
            ],
            notes,
        )


###############################################################################
# WAF Detection
###############################################################################


class Wafw00fTool(WebEnumerationTool):

    name = "wafw00f"
    description = "Detect Web Application Firewalls"

    def run(
        self,
        ctx: dict,
    ) -> ToolResult:

        if not is_tool_installed("wafw00f"):
            return _missing_tool(self.name)

        output = self.output_file(
            ctx,
            "wafw00f.txt",
        )

        logfile = self.output_file(
            ctx,
            "wafw00f.log",
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as report:

            for target in self.targets(ctx):

                command = (
                    f"wafw00f {_quote(target)}"
                )

                run_cmd(
                    command,
                    outfile=str(logfile),
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

        return ToolResult(
            self.name,
            True,
            [
                str(output),
                str(logfile),
            ],
            notes,
        ) 
###############################################################################
# FFUF Helpers
###############################################################################


def _select_wordlist() -> str | None:
    """
    Interactive FFUF wordlist selection.

    Returns
    -------
    str | None
        Valid wordlist path or None if invalid.
    """

    mode = questionary.select(
        "Choose FFUF wordlist:",
        choices=[
            "Auto-detect default",
            "Specify custom path",
        ],
    ).ask()

    if mode == "Auto-detect default":
        wordlist = find_default_web_fuzz_wordlist()

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

    if not is_valid_wordlist(wordlist):
        return None

    return wordlist


###############################################################################
# FFUF
###############################################################################


class FFUFTool(WebEnumerationTool):

    name = "ffuf"
    description = "Directory and content discovery"
    risk = "medium"

    def run(
        self,
        ctx: dict,
    ) -> ToolResult:

        if not is_tool_installed("ffuf"):
            return _missing_tool(self.name)

        if not questionary.confirm(
            "Run FFUF directory enumeration?"
        ).ask():
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped by user",
            )

        wordlist = _select_wordlist()

        if not wordlist:
            return ToolResult(
                self.name,
                False,
                [],
                "Invalid wordlist selected.",
            )

        enum_dir = self.enum_dir(ctx)

        logfile = enum_dir / "ffuf.log"

        summary = enum_dir / "ffuf.md"

        wordlist_file = (
            enum_dir /
            "wordlist_used.txt"
        )

        with wordlist_file.open(
            "w",
            encoding="utf-8",
        ) as fp:
            fp.write(wordlist + "\n")

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
                self.targets(ctx),
                start=1,
            ):

                report.write(
                    f"## Target {index}\n\n"
                )

                report.write(
                    f"{target}\n\n"
                )

                outfile = (
                    enum_dir /
                    f"ffuf_target_{index}.md"
                )

                command = (
                    "ffuf "
                    f"-u {_quote(target)}/FUZZ "
                    f"-w {_quote(wordlist)} "
                    "-mc all "
                    "-of md "
                    f"-o {_quote(str(outfile))}"
                )

                run_cmd(
                    command,
                    outfile=str(logfile),
                )

                if _safe_exists(outfile):

                    report.write(
                        f"Output: `{outfile.name}`\n\n"
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

        outputs = [
            str(summary),
            str(logfile),
            str(wordlist_file),
        ]

        for index, _ in enumerate(
            self.targets(ctx),
            start=1,
        ):

            outfile = (
                enum_dir /
                f"ffuf_target_{index}.md"
            )

            if _safe_exists(outfile):
                outputs.append(
                    str(outfile)
                )

        return ToolResult(
            self.name,
            True,
            outputs,
            notes,
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
# Module Metadata
###############################################################################

__all__ = [
    "WhatWebTool",
    "Wafw00fTool",
    "FFUFTool",
    "ALL_STAGE2_WEB_ENUM_TOOLS",
]
