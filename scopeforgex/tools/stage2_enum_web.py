import os
import questionary
from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.wordlists import find_default_wordlist, is_valid_wordlist
from scopeforgex.utils import build_notes_from_log


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
            return ToolResult(self.name, False, [], "whatweb not installed")

        run_cmd(f"whatweb https://{ctx['target']} > {out_txt}", outfile=out_log)

        notes = build_notes_from_log(out_log, "WhatWeb finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Target blocked/invalid?]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


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
            return ToolResult(self.name, False, [], "wafw00f not installed")

        run_cmd(f"wafw00f https://{ctx['target']} > {out_txt}", outfile=out_log)

        notes = build_notes_from_log(out_log, "wafw00f finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No output produced. Target unreachable?]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


class FFUFTool(ToolBase):
    name = "ffuf"
    stage = 2
    description = "Directory brute force"
    risk = "medium"

    def run(self, ctx: dict) -> ToolResult:
        enum_dir = os.path.join(ctx["outdir"], "enum")
        out_txt = os.path.join(enum_dir, "ffuf.md")
        out_log = os.path.join(enum_dir, "ffuf.log")

        if not is_tool_installed("ffuf"):
            return ToolResult(self.name, False, [], "ffuf not installed")

        run_it = questionary.confirm("Run ffuf directory bruteforce?").ask()
        if not run_it:
            return ToolResult(self.name, False, [], "Skipped by user")

        mode = questionary.select(
            "Choose wordlist mode:",
            choices=["Use default wordlist (auto-detect)", "Use custom wordlist path"],
        ).ask()

        if mode == "Use default wordlist (auto-detect)":
            wordlist = find_default_wordlist()
            if not wordlist:
                wordlist = questionary.text("No default found. Enter custom wordlist path:").ask()
        else:
            wordlist = questionary.text("Enter custom wordlist path:").ask()

        if not is_valid_wordlist(wordlist):
            return ToolResult(self.name, False, [], f"Invalid wordlist path: {wordlist}")

        with open(os.path.join(enum_dir, "wordlist_used.txt"), "w", encoding="utf-8") as f:
            f.write(wordlist + "\n")

        # ✅ ffuf can show 403/429 heavily (WAF/rate limit)
        run_cmd(
            f"ffuf -u https://{ctx['target']}/FUZZ -w {wordlist} -mc all -of md -o {out_txt}",
            outfile=out_log
        )

        notes = build_notes_from_log(out_log, "FFUF finished.")
        if not os.path.exists(out_txt) or os.path.getsize(out_txt) == 0:
            notes += " [No results or blocked/filtered target.]"

        return ToolResult(self.name, True, [out_txt, out_log], notes)


ALL_STAGE2_WEB_ENUM_TOOLS = [
    WhatwebTool(),
    Wafw00fTool(),
    FFUFTool(),
]
