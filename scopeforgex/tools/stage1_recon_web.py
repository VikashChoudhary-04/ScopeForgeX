import os
import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.wordlists import find_default_subdomain_wordlist, is_valid_wordlist
from scopeforgex.validators import looks_like_hostname


def _append_clean_hosts(input_path: str, output_path: str):
    """
    Reads any file, extracts hostnames only, appends to output_path.
    """
    if not os.path.exists(input_path):
        return

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.readlines()]

    cleaned = []
    for line in lines:
        if looks_like_hostname(line):
            cleaned.append(line.lower())

    # append cleaned
    with open(output_path, "a", encoding="utf-8") as out:
        for c in cleaned:
            out.write(c + "\n")


def _dedupe_file(path: str):
    if not os.path.exists(path):
        return 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.readlines() if x.strip()]

    seen = set()
    out_lines = []
    for l in lines:
        if l not in seen:
            seen.add(l)
            out_lines.append(l)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))

    return len(out_lines)


class Sublist3rTool(ToolBase):
    name = "sublist3r"
    stage = 1
    description = "Discover subdomains"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(self.name, False, [], "Skipped (not web target)")

        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_txt = os.path.join(recon_dir, "sublist3r.txt")
        out_log = os.path.join(recon_dir, "sublist3r.log")

        if not is_tool_installed("sublist3r"):
            return ToolResult(self.name, False, [], "sublist3r not installed")

        run_cmd(f"sublist3r -d {ctx['target']} -o {out_txt}", outfile=out_log, timeout=600)
        return ToolResult(self.name, True, [out_txt, out_log], "Sublist3r executed.")


class SubhuntTool(ToolBase):
    name = "subhunt"
    stage = 1
    description = "Subdomain bruteforce (wordlist)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(self.name, False, [], "Skipped (not web target)")

        recon_dir = os.path.join(ctx["outdir"], "recon")
        out_txt = os.path.join(recon_dir, "subhunt.txt")
        out_log = os.path.join(recon_dir, "subhunt.log")
        wordlist_file = os.path.join(recon_dir, "subhunt_wordlist_used.txt")

        if not is_tool_installed("subhunt"):
            return ToolResult(self.name, False, [], "subhunt not installed")

        run_it = questionary.confirm("Run Subhunt bruteforce?").ask()
        if not run_it:
            return ToolResult(self.name, False, [], "Skipped by user")

        mode = questionary.select(
            "Choose Subhunt wordlist mode:",
            choices=["Use default subdomain wordlist", "Use custom wordlist path"],
        ).ask()

        if mode == "Use default subdomain wordlist":
            wordlist = find_default_subdomain_wordlist()
            if not wordlist:
                wordlist = questionary.text("No default found. Enter custom wordlist path:").ask()
        else:
            wordlist = questionary.text("Enter custom wordlist path:").ask()

        if not is_valid_wordlist(wordlist):
            return ToolResult(self.name, False, [], f"Invalid wordlist path: {wordlist}")

        with open(wordlist_file, "w", encoding="utf-8") as f:
            f.write(wordlist + "\n")

        run_cmd(
            f"subhunt -d {ctx['target']} --bruteforce {wordlist} > {out_txt}",
            outfile=out_log,
            timeout=900
        )

        return ToolResult(self.name, True, [out_txt, out_log, wordlist_file], "Subhunt executed.")


class PipelineHostsBuilderTool(ToolBase):
    name = "pipeline_hosts_builder"
    stage = 1
    description = "Build pipeline host lists (raw/alive/final)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(self.name, False, [], "Skipped (not web target)")

        pipe = ctx.get("pipeline", {})
        hosts_raw = pipe.get("hosts_raw")
        hosts_alive = pipe.get("hosts_alive")
        hosts_final = pipe.get("hosts_final")

        recon_dir = os.path.join(ctx["outdir"], "recon")
        sublist = os.path.join(recon_dir, "sublist3r.txt")
        subhunt = os.path.join(recon_dir, "subhunt.txt")

        if not hosts_raw or not hosts_alive or not hosts_final:
            return ToolResult(self.name, False, [], "Pipeline paths missing in ctx")

        # Reset pipeline files
        open(hosts_raw, "w", encoding="utf-8").close()
        open(hosts_alive, "w", encoding="utf-8").close()
        open(hosts_final, "w", encoding="utf-8").close()

        # Always include main domain
        with open(hosts_raw, "a", encoding="utf-8") as f:
            f.write(ctx["target"].lower() + "\n")

        # Append from tools
        _append_clean_hosts(sublist, hosts_raw)
        _append_clean_hosts(subhunt, hosts_raw)

        raw_count = _dedupe_file(hosts_raw)

        # Alive check -> hosts_alive
        if not is_tool_installed("httpx"):
            return ToolResult(self.name, False, [hosts_raw], "httpx missing (can't build alive/final lists)")

        run_cmd(f"cat {hosts_raw} | httpx -silent > {hosts_alive}", outfile=os.path.join(ctx["outdir"], "recon", "httpx.log"), timeout=600)
        alive_count = _dedupe_file(hosts_alive)

        # Final = alive if available else raw
        if alive_count > 0:
            with open(hosts_alive, "r", encoding="utf-8") as f:
                data = f.read()
            with open(hosts_final, "w", encoding="utf-8") as f:
                f.write(data)
            final_count = alive_count
        else:
            with open(hosts_raw, "r", encoding="utf-8") as f:
                data = f.read()
            with open(hosts_final, "w", encoding="utf-8") as f:
                f.write(data)
            final_count = raw_count

        notes = f"hosts_raw={raw_count}, hosts_alive={alive_count}, hosts_final={final_count}"
        return ToolResult(self.name, True, [hosts_raw, hosts_alive, hosts_final], notes)


ALL_STAGE1_WEB_TOOLS = [
    Sublist3rTool(),
    SubhuntTool(),
    PipelineHostsBuilderTool(),
]
