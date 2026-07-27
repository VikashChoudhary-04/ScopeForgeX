"""
ScopeForgeX Stage 0 — Scope Validation
======================================

Responsible for:
- Authorization confirmation
- Target collection
- Target classification
- Pipeline initialization

v0.5.0
"""

from __future__ import annotations

import ipaddress
import re

from scopeforgex.ui import (
    stage,
    ok,
    warn,
)

from scopeforgex.stages.shared import pipeline_paths


###############################################################################
# Target Detection
###############################################################################


def _is_cidr(value: str) -> bool:
    """
    Detect IPv4/IPv6 CIDR ranges.
    """

    try:
        ipaddress.ip_network(
            value,
            strict=False,
        )

        return "/" in value

    except ValueError:

        return False



def _is_ip(value: str) -> bool:
    """
    Detect plain IP address.
    """

    try:

        ipaddress.ip_address(
            value
        )

        return True

    except ValueError:

        return False



def _is_ip_port(value: str) -> bool:
    """
    Detect IP:PORT targets.
    """

    pattern = (
        r"^\d{1,3}"
        r"(\.\d{1,3}){3}"
        r":\d+$"
    )

    return bool(
        re.match(
            pattern,
            value,
        )
    )



def _is_url(value: str) -> bool:
    """
    Detect HTTP/HTTPS URLs.
    """

    return value.startswith(
        (
            "http://",
            "https://",
        )
    )



def classify_target(
    target: str,
) -> str:
    """
    Classify target type.

    Returns:
        web
        network
    """

    if _is_cidr(
        target
    ):

        return "network"


    if (
        _is_url(target)
        or _is_ip_port(target)
        or _is_ip(target)
    ):

        return "web"


    return "web"



###############################################################################
# Pipeline Initialization
###############################################################################


def _initialize_pipeline(
    ctx: dict,
) -> None:

    ctx[
        "pipeline"
    ] = pipeline_paths(
        ctx["outdir"]
    )



###############################################################################
# Stage Entry
###############################################################################


def stage0_scope(
    ctx: dict,
) -> None:
    """
    Validate scope and initialize workflow context.
    """

    stage(
        "STAGE 0 — SCOPE & LEGAL CHECK",
        "blue",
    )


    authorized = input(
        "Do you have written authorization? (yes/no): "
    ).strip().lower()


    if authorized not in (
        "yes",
        "y",
    ):

        raise RuntimeError(
            "Authorization not confirmed."
        )


    target = input(
        "Enter target: "
    ).strip()


    if not target:

        raise RuntimeError(
            "Target cannot be empty."
        )


    target_type = classify_target(
        target
    )


    ctx[
        "target"
    ] = target


    ctx[
        "target_type"
    ] = target_type


    safe_name = (
        target
        .replace(
            "://",
            "_",
        )
        .replace(
            "/",
            "_",
        )
        .replace(
            ":",
            "_",
        )
    )


    ctx[
        "outdir"
    ] = (
        f"outputs/{safe_name}"
    )


    _initialize_pipeline(
        ctx
    )


    ok(
        f"Target set: {target}"
    )


    if target_type == "network":

        warn(
            "Network target detected. "
            "Web application discovery will be skipped."
        )
