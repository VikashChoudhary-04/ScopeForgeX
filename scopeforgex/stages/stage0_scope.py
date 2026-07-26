"""
ScopeForgeX Stage 0
===================

Scope definition and legal authorization.

This stage:
- Verifies authorization
- Collects the target
- Validates the target
- Creates the output directory structure
- Initializes the pipeline context

v0.4.0
"""

from __future__ import annotations

import questionary

from scopeforgex.stages.shared import init_output_dirs, pipeline_paths
from scopeforgex.ui import err, ok, stage
from scopeforgex.utils import load_yaml
from scopeforgex.validators import (
    is_valid_domain,
    is_valid_ip_or_cidr,
)


def _abort(message: str):
    """
    Display an error and terminate execution.
    """

    err(message)
    raise SystemExit(1)


def stage0_scope(ctx: dict):
    """
    Initialize workflow scope and execution context.
    """

    stage("STAGE 0 — SCOPE & LEGAL CHECK", "blue")

    authorized = questionary.confirm(
        "Do you have written authorization?"
    ).ask()

    if not authorized:
        _abort("STOP: Written authorization required.")

    target_type = questionary.select(
        "Choose target type:",
        choices=[
            "Web / Domain",
            "Network / IP Range",
        ],
    ).ask()

    config = load_yaml("config/default.yaml")
    base_dir = config.get("output_base_dir", "outputs")

    if target_type == "Web / Domain":

        target = (
            questionary.text(
                "Enter domain (example.com):"
            ).ask()
            or ""
        ).strip()

        if not is_valid_domain(target):
            _abort("Invalid domain format.")

        ctx["target_type"] = "web"
        ctx["target"] = target

        output_name = target.replace(".", "_")

    else:

        target = (
            questionary.text(
                "Enter IP / range (e.g. 10.10.10.0/24):"
            ).ask()
            or ""
        ).strip()

        if not is_valid_ip_or_cidr(target):
            _abort("Invalid IP/range.")

        ctx["target_type"] = "network"
        ctx["target"] = target

        output_name = "network_target"

    ctx["outdir"] = init_output_dirs(
        base_dir,
        output_name,
    )

    ctx["pipeline"] = pipeline_paths(
        ctx["outdir"]
    )

    ok(f"Target set: {ctx['target']}")
