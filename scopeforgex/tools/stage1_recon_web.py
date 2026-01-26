import os
import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.wordlists import find_default_subdomain_wordlist, is_valid_wordlist
from scopeforgex.validators import looks_like_hostname


def _append_clean_hosts(input_path: str, output_path: str):
    if not os.path.exists(input_path):
        return

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.readlines()]

    cleaned = []
    for line in lines:
        if looks_like_hostname(line):
            cleaned.append(line.lower())

    with open(output_path, "a", encoding="utf-8") as out:
        for c in cleaned:
            out.write(c + "\n")


def _append_clean_urls(input_path: str, output_path: str):
    if not os.path.exists(input_path):
        return

    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [x.strip() for x in f.readlines()]

    cleaned = []
    for line in lines:
        if line.startswith("http://") or line.startswith("https://"):
            cleaned.append(line)

    with open(output_path, "a", encoding="utf-8") as out:
        for c in cleaned:
            out.write(c + "\n")


def _dedupe_file(path: str) -> int:
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


class SubhuntTool(ToolBase):
    name = "subhunt"
    stage = 1
    description = "Subhunt finds subdomains (FAST pipeline root)"
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
            choices=[
                "Use default subdomain wordlist (auto-detect)",
                "Use custom wordlist path",
            ],
        ).ask()

        if mode == "Use default subdomain wordlist (auto-detect)":
            wordlist = find_default_subdomain_wordlist()
            if not wordlist:
                wordlist = questionary.text("No default found. Enter custom wordlist path:").ask()
        else:
            wordlist = questionary.text("Enter custom wordlist path:").ask()

        if not is_valid_wordlist(wordlist):
            return ToolResult(self.name, False, [], f"Invalid wordlist path: {wordlist}")

        with open(wordlist_file, "w", encoding="utf-8") as f:
            f.write(wordlist + "\n")

        # ✅ Subhunt is the FIRST truth source in FAST
        run_cmd(
            f"subhunt -d {ctx['target']} --bruteforce {wordlist} > {out_txt}",
            outfile=out_log,
            timeout=900
        )

        return ToolResult(self.name, True, [out_txt, out_log, wordlist_file], "Subhunt completed.")


class FastPipelineBuilderTool(ToolBase):
    name = "pipeline_builder"
    stage = 1
    description = "FAST pipeline: subhunt -> alive -> endpoints"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(self.name, False, [], "Skipped (not web target)")

        pipe = ctx.get("pipeline", {})
        hosts_raw = pipe.get("hosts_raw")
        hosts_alive = pipe.get("hosts_alive")
        hosts_final = pipe.get("hosts_final")
        urls_raw = pipe.get("urls_raw")
        urls_final = pipe.get("urls_final")

        if not all([hosts_raw, hosts_alive, hosts_final, urls_raw, urls_final]):
            return ToolResult(self.name, False, [], "Pipeline paths missing in ctx")

        recon_dir = os.path.join(ctx["outdir"], "recon")

        subhunt_out = os.path.join(recon_dir, "subhunt.txt")
        httpx_log = os.path.join(recon_dir, "httpx.log")

        katana_out = os.path.join(recon_dir, "katana.txt")
        katana_log = os.path.join(recon_dir, "katana.log")

        # Reset pipeline files
        open(hosts_raw, "w", encoding="utf-8").close()
        open(hosts_alive, "w", encoding="utf-8").close()
        open(hosts_final, "w", encoding="utf-8").close()
        open(urls_raw, "w", encoding="utf-8").close()
        open(urls_final, "w", encoding="utf-8").close()

        # ✅ FAST: hosts_raw must come ONLY from Subhunt output
        _append_clean_hosts(subhunt_out, hosts_raw)
        raw_count = _dedupe_file(hosts_raw)

        if raw_count == 0:
            return ToolResult(self.name, False, [hosts_raw], "No subdomains found by Subhunt (hosts_raw empty)")

        # Alive filtering
        if not is_tool_installed("httpx"):
            return ToolResult(self.name, False, [hosts_raw], "httpx missing (can't build alive/final)")

        run_cmd(f"cat {hosts_raw} | httpx -silent > {hosts_alive}", outfile=httpx_log, timeout=600)
        alive_count = _dedupe_file(hosts_alive)

        if alive_count == 0:
            return ToolResult(self.name, False, [hosts_raw, hosts_alive], "No alive subdomains found (hosts_alive empty)")

        # hosts_final = alive only
        with open(hosts_alive, "r", encoding="utf-8") as f:
            data = f.read()
        with open(hosts_final, "w", encoding="utf-8") as f:
            f.write(data)

        final_count = _dedupe_file(hosts_final)

        # ✅ Endpoints ONLY from alive subdomains
        notes_parts = [f"hosts_raw={raw_count}", f"hosts_alive={alive_count}", f"hosts_final={final_count}"]

        if is_tool_installed("katana"):
            run_cmd(
                f"cat {hosts_final} | katana -silent > {katana_out}",
                outfile=katana_log,
                timeout=600
            )
            _append_clean_urls(katana_out, urls_raw)

        url_count_raw = _dedupe_file(urls_raw)

        # urls_final = urls_raw
        with open(urls_raw, "r", encoding="utf-8") as f:
            data = f.read()
        with open(urls_final, "w", encoding="utf-8") as f:
            f.write(data)

        url_count_final = _dedupe_file(urls_final)

        notes_parts.append(f"urls_raw={url_count_raw}")
        notes_parts.append(f"urls_final={url_count_final}")

        outputs = [
            hosts_raw, hosts_alive, hosts_final,
            urls_raw, urls_final,
            httpx_log
        ]

        if os.path.exists(katana_out):
            outputs += [katana_out, katana_log]

        return ToolResult(self.name, True, outputs, " | ".join(notes_parts))


ALL_STAGE1_WEB_TOOLS = [
    SubhuntTool(),
    FastPipelineBuilderTool(),
]
