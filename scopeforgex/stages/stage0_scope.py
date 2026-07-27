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

v0.4.1
"""

from __future__ import annotations

from typing import NoReturn

import questionary

from scopeforgex.stages.shared import (
    init_output_dirs,
    pipeline_paths,
)
from scopeforgex.ui import err, ok, stage
from scopeforgex.utils import load_yaml
from scopeforgex.validators import (
    is_valid_domain,
    is_valid_ip_or_cidr,
)

###############################################################################
# Constants
###############################################################################

TARGET_WEB = "web"
TARGET_NETWORK = "network"

WEB_LABEL = "Web / Domain"
NETWORK_LABEL = "Network / IP Range"


###############################################################################
# Helpers
###############################################################################


def _abort(message: str) -> NoReturn:
    """
    Display an error and terminate execution.
    """

    err(message)
    raise SystemExit(1)


def _get_web_target() -> tuple[str, str]:
    """
    Collect and validate a web target.

    Returns
    -------
    tuple[str, str]
        (target, output_directory_name)
    """

    target = (
        questionary.text(
            "Enter domain (example.com):"
        ).ask()
        or ""
    ).strip()

    if not is_valid_domain(target):
        _abort("Invalid domain format.")

    output_name = target.replace(".", "_")

    return target, output_name


def _get_network_target() -> tuple[str, str]:
    """
    Collect and validate a network target.

    Returns
    -------
    tuple[str, str]
        (target, output_directory_name)
    """

    target = (
        questionary.text(
            "Enter IP / range (e.g. 10.10.10.0/24):"
        ).ask()
        or ""
    ).strip()

    if not is_valid_ip_or_cidr(target):
        _abort("Invalid IP/range.")

    output_name = (
        target.replace("/", "_")
        .replace(".", "_")
        .replace(":", "_")
    )

    return target, output_name


def _initialize_pipeline(
    ctx: dict[str, object],
    base_dir: str,
    output_name: str,
) -> None:
    """
    Initialize the output directory structure and
    pipeline paths.
    """

    outdir = init_output_dirs(
        base_dir,
        output_name,
    )

    ctx["outdir"] = outdir
    ctx["pipeline"] = pipeline_paths(
        outdir,
    )


###############################################################################
# Stage
###############################################################################


def stage0_scope(
    ctx: dict[str, object],
) -> None:
    """
    Initialize workflow scope and execution context.
    """

    stage(
        "STAGE 0 — SCOPE & LEGAL CHECK",
        "blue",
    )

    authorized = questionary.confirm(
        "Do you have written authorization?"
    ).ask()

    if not authorized:
        _abort(
            "STOP: Written authorization required."
        )

    target_selection = questionary.select(
        "Choose target type:",
        choices=[
            WEB_LABEL,
            NETWORK_LABEL,
        ],
    ).ask()

    config = load_yaml(
        "config/default.yaml"
    )

    base_dir = config.get(
        "output_base_dir",
        "outputs",
    )

    if target_selection == WEB_LABEL:

        target, output_name = _get_web_target()

        ctx["target_type"] = TARGET_WEB

    else:

        target, output_name = _get_network_target()

        ctx["target_type"] = TARGET_NETWORK

    ctx["target"] = target

    _initialize_pipeline(
        ctx,
        base_dir,
        output_name,
    )

    ok(
        f"Target set: {target}"
    )


###############################################################################
# Public Exports
###############################################################################

__all__ = [
    "stage0_scope",
]
