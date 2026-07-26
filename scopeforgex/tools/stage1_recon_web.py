import os
import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.wordlists import (
    find_default_subdomain_wordlist,
    is_valid_wordlist,
)
from scopeforgex.validators import looks_like_hostname


def _append_clean_hosts(input_path: str, output_path: str):
    """
    Append valid hostnames from input_path into output_path.
    """

    if not os.path.exists(input_path):
        return

    with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
        hosts = [
            line.strip().lower()
            for line in infile
            if looks_like_hostname(line.strip())
        ]

    with open(output_path, "a", encoding="utf-8") as outfile:
        for host in hosts:
            outfile.write(host + "\n")


def _append_clean_urls(input_path: str, output_path: str):
    """
    Append only HTTP/HTTPS URLs from input_path.
    """

    if not os.path.exists(input_path):
        return

    with open(input_path, "r", encoding="utf-8", errors="ignore") as infile:
        urls = [
            line.strip()
            for line in infile
            if line.strip().startswith(("http://", "https://"))
        ]

    with open(output_path, "a", encoding="utf-8") as outfile:
        for url in urls:
            outfile.write(url + "\n")


def _dedupe_file(path: str) -> int:
    """
    Remove duplicate lines while preserving order.

    Returns:
        int: Number of unique entries.
    """

    if not os.path.exists(path):
        return 0

    with open(path, "r", encoding="utf-8", errors="ignore") as infile:
        lines = [line.strip() for line in infile if line.strip()]

    unique = list(dict.fromkeys(lines))

    with open(path, "w", encoding="utf-8") as outfile:
        if unique:
            outfile.write("\n".join(unique) + "\n")

    return len(unique)


class SubhuntTool(ToolBase):
    name = "subhunt"
    stage = 1
    description = "Subhunt finds subdomains (FAST pipeline root)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped (not web target)",
            )

        recon_dir = os.path.join(ctx["outdir"], "recon")

        out_txt = os.path.join(recon_dir, "subhunt.txt")
        out_log = os.path.join(recon_dir, "subhunt.log")
        wordlist_used = os.path.join(
            recon_dir,
            "subhunt_wordlist_used.txt",
        )

        if not is_tool_installed("subhunt"):
            return ToolResult(
                self.name,
                False,
                [],
                "subhunt not installed",
            )

        if not questionary.confirm(
            "Run Subhunt bruteforce?"
        ).ask():
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped by user",
            )

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
            f"subhunt -d {ctx['target']} --bruteforce {wordlist} > {out_txt}",
            outfile=out_log,
            timeout=900,
        )

        return ToolResult(
            self.name,
            True,
            [
                out_txt,
                out_log,
                wordlist_used,
            ],
            "Subhunt completed.",
        )


class FastPipelineBuilderTool(ToolBase):
    name = "pipeline_builder"
    stage = 1
    description = "FAST pipeline: subhunt -> alive -> endpoints"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:
        if ctx.get("target_type") != "web":
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped (not web target)",
            )

        pipe = ctx.get("pipeline", {})

        required = (
            "hosts_raw",
            "hosts_alive",
            "hosts_final",
            "urls_raw",
            "urls_final",
        )

        if not all(pipe.get(x) for x in required):
            return ToolResult(
                self.name,
                False,
                [],
                "Pipeline paths missing in ctx",
            )

        hosts_raw = pipe["hosts_raw"]
        hosts_alive = pipe["hosts_alive"]
        hosts_final = pipe["hosts_final"]
        urls_raw = pipe["urls_raw"]
        urls_final = pipe["urls_final"]

        recon_dir = os.path.join(ctx["outdir"], "recon")

        subhunt_out = os.path.join(recon_dir, "subhunt.txt")
        httpx_log = os.path.join(recon_dir, "httpx.log")
        katana_out = os.path.join(recon_dir, "katana.txt")
        katana_log = os.path.join(recon_dir, "katana.log")

        if not os.path.exists(hosts_raw):
            open(hosts_raw, "w", encoding="utf-8").close()

        for path in (
            hosts_alive,
            hosts_final,
            urls_raw,
            urls_final,
        ):
            open(path, "w", encoding="utf-8").close()

        _append_clean_hosts(subhunt_out, hosts_raw)
        raw_count = _dedupe_file(hosts_raw)

        if raw_count == 0:
            with open(hosts_raw, "a", encoding="utf-8") as f:
                f.write(ctx["target"].lower() + "\n")

            raw_count = _dedupe_file(hosts_raw)

        if not is_tool_installed("httpx"):
            return ToolResult(
                self.name,
                False,
                [hosts_raw],
                "httpx missing (can't build alive/final)",
            )

        run_cmd(
            f"cat {hosts_raw} | httpx -silent > {hosts_alive}",
            outfile=httpx_log,
            timeout=600,
        )

        alive_count = _dedupe_file(hosts_alive)

        if alive_count == 0:
            return ToolResult(
                self.name,
                False,
                [
                    hosts_raw,
                    hosts_alive,
                ],
                "No alive hosts found by httpx (hosts_alive empty)",
            )

        with open(hosts_alive, "r", encoding="utf-8") as src:
            alive_data = src.read()

        with open(hosts_final, "w", encoding="utf-8") as dst:
            dst.write(alive_data)

        final_count = _dedupe_file(hosts_final)

        notes = [
            f"hosts_raw={raw_count}",
            f"hosts_alive={alive_count}",
            f"hosts_final={final_count}",
        ]

        if is_tool_installed("katana"):
            run_cmd(
                f"cat {hosts_final} | katana -silent > {katana_out}",
                outfile=katana_log,
                timeout=600,
            )

            _append_clean_urls(katana_out, urls_raw)

        raw_urls = _dedupe_file(urls_raw)

        with open(urls_raw, "r", encoding="utf-8") as src:
            url_data = src.read()

        with open(urls_final, "w", encoding="utf-8") as dst:
            dst.write(url_data)

        final_urls = _dedupe_file(urls_final)

        notes.extend(
            [
                f"urls_raw={raw_urls}",
                f"urls_final={final_urls}",
            ]
        )

        outputs = [
            hosts_raw,
            hosts_alive,
            hosts_final,
            urls_raw,
            urls_final,
            httpx_log,
        ]

        if os.path.exists(katana_out):
            outputs.extend(
                [
                    katana_out,
                    katana_log,
                ]
            )

        return ToolResult(
            self.name,
            True,
            outputs,
            " | ".join(notes),
        )


ALL_STAGE1_WEB_TOOLS = [
    SubhuntTool(),
    FastPipelineBuilderTool(),
]
