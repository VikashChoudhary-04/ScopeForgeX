"""
ScopeForgeX Stage 1 - Web Recon Tools
=====================================

Web reconnaissance implementations.

Tools:
    • Subhunt
    • Pipeline Builder

v0.5.2

Supports:
    - Domains
    - Web applications hosted on IP addresses
    - Local labs (Juice Shop, DVWA, bWAPP)
"""

from __future__ import annotations

import os

import questionary

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.wordlists import (
    find_default_subdomain_wordlist,
    is_valid_wordlist,
)
from scopeforgex.validators import looks_like_hostname


###############################################################################
# Helpers
###############################################################################


def _is_ip_web_target(
    target: str,
) -> bool:
    """
    Detect IP based web application targets.

    Examples:
        192.168.1.10
        192.168.1.10:3000
        http://192.168.1.10:3000
    """

    return (
        target.startswith("http://")
        or target.startswith("https://")
        or ":" in target
    )



def _normalize_url(
    target: str,
) -> str:
    """
    Convert IP:PORT into URL.
    """

    if target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        return target

    return (
        "http://"
        + target
    )



def _append_clean_hosts(
    input_path: str,
    output_path: str,
) -> None:
    """
    Append valid hosts from a discovery file.
    """

    if not os.path.exists(input_path):
        return

    with open(
        input_path,
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

    with open(
        output_path,
        "a",
        encoding="utf-8",
    ) as outfile:

        for host in hosts:
            outfile.write(
                host + "\n"
            )



def _append_clean_urls(
    input_path: str,
    output_path: str,
) -> None:
    """
    Append HTTP/HTTPS URLs only.
    """

    if not os.path.exists(input_path):
        return

    with open(
        input_path,
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

    with open(
        output_path,
        "a",
        encoding="utf-8",
    ) as outfile:

        for url in urls:
            outfile.write(
                url + "\n"
            )



def _dedupe_file(
    path: str,
) -> int:
    """
    Remove duplicate lines.
    """

    if not os.path.exists(path):
        return 0

    with open(
        path,
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

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as outfile:

        if unique:
            outfile.write(
                "\n".join(unique)
                + "\n"
            )

    return len(unique)



###############################################################################
# Subhunt
###############################################################################


class SubhuntTool(ToolBase):

    name = "subhunt"
    stage = 1
    description = "Subhunt finds subdomains"
    risk = "low"


    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        target = ctx.get(
            "target",
            "",
        )


        if ctx.get(
            "target_type"
        ) != "web":

            return ExecutionResult.skipped(
                tool=self.name,
                capability="subdomain_discovery",
                reason="Skipped (not web target)",
            )


        if _is_ip_web_target(
            target
        ):

            return ExecutionResult.skipped(
                tool=self.name,
                capability="subdomain_discovery",
                reason="Skipped for IP/web application target",
            )


        recon_dir = os.path.join(
            ctx["outdir"],
            "recon",
        )


        out_txt = os.path.join(
            recon_dir,
            "subhunt.txt",
        )

        out_log = os.path.join(
            recon_dir,
            "subhunt.log",
        )

        wordlist_used = os.path.join(
            recon_dir,
            "subhunt_wordlist_used.txt",
        )


        if not is_tool_installed(
            "subhunt"
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability="subdomain_discovery",
                error="subhunt not installed",
            )


        if not questionary.confirm(
            "Run Subhunt bruteforce?"
        ).ask():

            return ExecutionResult.skipped(
                tool=self.name,
                capability="subdomain_discovery",
                reason="Skipped by user",
            )


        mode = questionary.select(
            "Choose Subhunt wordlist mode:",
            choices=[
                "Use default subdomain wordlist (auto-detect)",
                "Use custom wordlist path",
            ],
        ).ask()


        if mode.startswith(
            "Use default"
        ):

            wordlist = find_default_subdomain_wordlist()

            if not wordlist:

                wordlist = questionary.text(
                    "Enter custom wordlist path:"
                ).ask()

        else:

            wordlist = questionary.text(
                "Enter custom wordlist path:"
            ).ask()


        if not is_valid_wordlist(
            wordlist
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability="subdomain_discovery",
                error=f"Invalid wordlist path: {wordlist}",
            )


        with open(
            wordlist_used,
            "w",
            encoding="utf-8",
        ) as file:

            file.write(
                wordlist + "\n"
            )


        run_cmd(
            f"subhunt -d {target} --bruteforce {wordlist} > {out_txt}",
            outfile=out_log,
            timeout=900,
        )


        return ExecutionResult.success_result(
            tool=self.name,
            capability="subdomain_discovery",
            artifacts=[
                out_txt,
                out_log,
                wordlist_used,
            ],
            metadata={
                "message": "Subhunt completed.",
            },
        )
###############################################################################
# Fast Pipeline Builder
###############################################################################


class FastPipelineBuilderTool(ToolBase):

    name = "pipeline_builder"
    stage = 1
    description = "FAST pipeline: hosts -> alive -> endpoints"
    risk = "low"


    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        if ctx.get(
            "target_type"
        ) != "web":

            return ExecutionResult.skipped(
                tool=self.name,
                capability="web_asset_pipeline",
                reason="Skipped (not web target)",
            )


        pipe = ctx.get(
            "pipeline",
            {},
        )


        hosts_raw = pipe["hosts_raw"]
        hosts_alive = pipe["hosts_alive"]
        hosts_final = pipe["hosts_final"]

        urls_raw = pipe["urls_raw"]
        urls_final = pipe["urls_final"]


        recon_dir = os.path.join(
            ctx["outdir"],
            "recon",
        )


        os.makedirs(
            recon_dir,
            exist_ok=True,
        )


        httpx_log = os.path.join(
            recon_dir,
            "httpx.log",
        )


        for path in (
            hosts_raw,
            hosts_alive,
            hosts_final,
            urls_raw,
            urls_final,
        ):

            open(
                path,
                "w",
                encoding="utf-8",
            ).close()


        target = ctx.get(
            "target",
            "",
        )


        #######################################################################
        # IP/Web Application Pipeline
        #######################################################################

        if _is_ip_web_target(
            target
        ):

            url = _normalize_url(
                target
            )

            for path in (
                hosts_raw,
                hosts_alive,
                hosts_final,
                urls_raw,
                urls_final,
            ):

                with open(
                    path,
                    "w",
                    encoding="utf-8",
                ) as file:

                    file.write(
                        url + "\n"
                    )


            return ExecutionResult.success_result(
                tool=self.name,
                capability="web_asset_pipeline",
                artifacts=[
                    hosts_raw,
                    hosts_alive,
                    hosts_final,
                    urls_raw,
                    urls_final,
                ],
                metadata={
                    "message": (
                        "IP/web application "
                        "pipeline completed."
                    ),
                    "target": url,
                    "mode": "direct_url",
                },
            )


        #######################################################################
        # Domain Pipeline
        #######################################################################

        subhunt_out = os.path.join(
            recon_dir,
            "subhunt.txt",
        )


        _append_clean_hosts(
            subhunt_out,
            hosts_raw,
        )


        raw_count = _dedupe_file(
            hosts_raw,
        )


        if raw_count == 0:

            with open(
                hosts_raw,
                "a",
                encoding="utf-8",
            ) as file:

                file.write(
                    target.lower()
                    + "\n"
                )


            raw_count = _dedupe_file(
                hosts_raw
            )


        if not is_tool_installed(
            "httpx"
        ):

            return ExecutionResult.failure(
                tool=self.name,
                capability="web_asset_pipeline",
                error="httpx missing",
                artifacts=[
                    hosts_raw,
                ],
            )


        run_cmd(
            f"cat {hosts_raw} | httpx -silent > {hosts_alive}",
            outfile=httpx_log,
            timeout=600,
        )


        alive_count = _dedupe_file(
            hosts_alive
        )


        if alive_count == 0:

            return ExecutionResult.failure(
                tool=self.name,
                capability="web_asset_pipeline",
                error="No alive hosts found by httpx",
                artifacts=[
                    hosts_raw,
                    hosts_alive,
                ],
            )


        with open(
            hosts_alive,
            "r",
            encoding="utf-8",
        ) as source, open(
            hosts_final,
            "w",
            encoding="utf-8",
        ) as destination:

            destination.write(
                source.read()
            )


        final_count = _dedupe_file(
            hosts_final
        )


        if is_tool_installed(
            "katana"
        ):

            katana_out = os.path.join(
                recon_dir,
                "katana.txt",
            )

            katana_log = os.path.join(
                recon_dir,
                "katana.log",
            )


            run_cmd(
                f"cat {hosts_final} | katana -silent > {katana_out}",
                outfile=katana_log,
                timeout=600,
            )


            _append_clean_urls(
                katana_out,
                urls_raw,
            )


        raw_urls = _dedupe_file(
            urls_raw
        )


        with open(
            urls_raw,
            "r",
            encoding="utf-8",
        ) as source, open(
            urls_final,
            "w",
            encoding="utf-8",
        ) as destination:

            destination.write(
                source.read()
            )


        final_urls = _dedupe_file(
            urls_final
        )


        return ExecutionResult.success_result(
            tool=self.name,
            capability="web_asset_pipeline",
            artifacts=[
                hosts_raw,
                hosts_alive,
                hosts_final,
                urls_raw,
                urls_final,
                httpx_log,
            ],
            metadata={
                "message": (
                    "Web asset pipeline completed."
                ),
                "hosts_raw": raw_count,
                "hosts_alive": alive_count,
                "hosts_final": final_count,
                "urls_raw": raw_urls,
                "urls_final": final_urls,
            },
        )


###############################################################################
# Registry Export
###############################################################################


ALL_STAGE1_WEB_TOOLS = [
    SubhuntTool(),
    FastPipelineBuilderTool(),
]
