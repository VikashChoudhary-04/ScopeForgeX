"""
ScopeForgeX Stage 1 Web Recon Tools
===================================

Reconnaissance tools for web targets.

Includes:
    - Subhunt integration
    - FAST pipeline builder

v0.5.3
"""

from __future__ import annotations

import ipaddress
import os

import questionary

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed

from scopeforgex.wordlists import (
    find_default_subdomain_wordlist,
    is_valid_wordlist,
)


###############################################################################
# Target Helpers
###############################################################################


def _is_ip_web_target(
    target: str,
) -> bool:
    """
    Check whether target is an IP based web application.
    """

    value = (
        target
        .replace(
            "http://",
            "",
        )
        .replace(
            "https://",
            "",
        )
        .split(
            ":"
        )[0]
        .strip()
    )

    try:

        ipaddress.ip_address(
            value
        )

        return True

    except ValueError:

        return False



###############################################################################
# Helpers
###############################################################################


def _count_lines(
    path: str,
) -> int:
    """
    Count non-empty lines.
    """

    if not os.path.exists(
        path
    ):
        return 0

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        return sum(
            1
            for line in file
            if line.strip()
        )



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


        os.makedirs(
            recon_dir,
            exist_ok=True,
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


        run_command(
            tool=self.name,
            capability="subdomain_discovery",
            cmd=f"subhunt -d {target} --bruteforce {wordlist} > {out_txt}",
            outfile=out_log,
            timeout=900,
        )


        artifacts = [
            artifact
            for artifact in (
                out_txt,
                out_log,
                wordlist_used,
            )
            if os.path.exists(
                artifact
            )
        ]


        return ExecutionResult.success_result(
            tool=self.name,
            capability="subdomain_discovery",
            artifacts=artifacts,
            metadata={
                "message": "Subhunt completed.",
                "subdomains_found": _count_lines(
                    out_txt
                ),
            },
        )
###############################################################################
# FAST Pipeline Builder
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

            url = (
                target
                if target.startswith(
                    "http"
                )
                else f"http://{target}"
            )


            for path, value in (
                (hosts_raw, target),
                (hosts_alive, target),
                (hosts_final, target),
                (urls_raw, url),
                (urls_final, url),
            ):

                with open(
                    path,
                    "w",
                    encoding="utf-8",
                ) as file:

                    file.write(
                        value + "\n"
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
                    "message": "IP/web application pipeline completed.",
                    "mode": "direct_url",
                    "target": url,
                },
            )


        #######################################################################
        # Domain Pipeline
        #######################################################################

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
                "message": "Domain pipeline completed.",
                "mode": "domain",
                "target": target,
            },
        )


###############################################################################
# Registry Export
###############################################################################


ALL_STAGE1_WEB_TOOLS = [
    SubhuntTool(),
    FastPipelineBuilderTool(),
]


__all__ = [
    "SubhuntTool",
    "FastPipelineBuilderTool",
    "ALL_STAGE1_WEB_TOOLS",
]
