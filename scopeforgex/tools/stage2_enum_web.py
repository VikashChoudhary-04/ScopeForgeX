import os

import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.utils import build_notes_from_log
from scopeforgex.wordlists import (
    find_default_web_fuzz_wordlist,
    is_valid_wordlist,
)


def _get_targets(ctx: dict):
    """
    Return the list of web targets to enumerate.

    Preference:
        1. Stage 1 hosts_final
        2. Root target
    """

    targets = [f"https://{ctx['target']}"]

    pipeline = ctx.get("pipeline", {})
    hosts_final = pipeline.get("hosts_final")

    if hosts_final and os.path.exists(hosts_final):
        with open(hosts_final, encoding="utf-8") as f:
            hosts = [line.strip() for line in f if line.strip()]

        if hosts:
            targets = hosts

    return targets


class WhatwebTool(ToolBase):
    name = "whatweb"
    stage = 2
    description = "Web fingerprinting"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        enum_dir = os.path.join(ctx["outdir"], "enum")

        out_txt = os.path.join(enum_dir, "whatweb.txt")
        out_log = os.path.join(enum_dir, "whatweb.log")

        if not is_tool_installed("whatweb"):
            return ToolResult(
                self.name,
                False,
                [],
                "whatweb not installed",
            )

        with open(out_txt, "w", encoding="utf-8") as output:
            for target in _get_targets(ctx):
                run_cmd(
                    f"whatweb {target}",
                    outfile=out_log,
                )
                output.write(f"Scanned: {target}\n")

        notes = build_notes_from_log(
            out_log,
            "WhatWeb finished.",
        )

        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Target blocked/invalid?]"

        return ToolResult(
            self.name,
            True,
            [
                out_txt,
                out_log,
            ],
            notes,
        )


class Wafw00fTool(ToolBase):
    name = "wafw00f"
    stage = 2
    description = "WAF detection"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        enum_dir = os.path.join(ctx["outdir"], "enum")

        out_txt = os.path.join(enum_dir, "wafw00f.txt")
        out_log = os.path.join(enum_dir, "wafw00f.log")

        if not is_tool_installed("wafw00f"):
            return ToolResult(
                self.name,
                False,
                [],
                "wafw00f not installed",
            )

        with open(out_txt, "w", encoding="utf-8") as output:
            for target in _get_targets(ctx):
                run_cmd(
                    f"wafw00f {target}",
                    outfile=out_log,
                )
                output.write(f"Scanned: {target}\n")

        notes = build_notes_from_log(
            out_log,
            "wafw00f finished.",
        )

        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Target unreachable?]"

        return ToolResult(
            self.name,
            True,
            [
                out_txt,
                out_log,
            ],
            notes,
        )


class FFUFTool(ToolBase):
    name = "ffuf"
    stage = 2
    description = "Directory brute force"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        enum_dir = os.path.join(ctx["outdir"], "enum")

        out_txt = os.path.join(enum_dir, "ffuf.md")
        out_log = os.path.join(enum_dir, "ffuf.log")

        wordlist_used = os.path.join(
            enum_dir,
            "wordlist_used.txt",
        )

        if not is_tool_installed("ffuf"):
            return ToolResult(
                self.name,
                False,
                [],
                "ffuf not installed",
            )

        if not questionary.confirm(
            "Run ffuf directory bruteforce?"
        ).ask():
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped by user",
            )

        mode = questionary.select(
            "Choose FFUF wordlist mode:",
            choices=[
                "Use default web wordlist (auto-detect)",
                "Use custom wordlist path",
            ],
        ).ask()

        if mode == "Use default web wordlist (auto-detect)":
            wordlist = find_default_web_fuzz_wordlist()

            if not wordlist:
                wordlist = questionary.text(
                    "No default found. Enter custom wordlist path:"
                ).ask()
        else:
            wordlist = questionary.text(
                "Enter custom wordlist path:"
            ).ask()

        if not is_valid_wordlist(wordlist):
            return ToolResult(
                self.name,
                False,
                [],
                f"Invalid wordlist path: {wordlist}",
            )

        with open(wordlist_used, "w", encoding="utf-8") as f:
            f.write(wordlist + "\n")

        run_cmd(
            f"ffuf -u https://{ctx['target']}/FUZZ "
            f"-w {wordlist} "
            f"-mc all "
            f"-of md "
            f"-o {out_txt}",
            outfile=out_log,
        )

        notes = build_notes_from_log(
            out_log,
            "FFUF finished.",
        )

        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No results or blocked/filtered target.]"

        return ToolResult(
            self.name,
            True,
            [
                out_txt,
                out_log,
                wordlist_used,
            ],
            notes,
        )


ALL_STAGE2_WEB_ENUM_TOOLS = [
    WhatwebTool(),
    Wafw00fTool(),
    FFUFTool(),
]
