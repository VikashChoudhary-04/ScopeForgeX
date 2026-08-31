"""
ScopeForgeX Stage 0 — Scope Validation
======================================

Responsible for:
- Authorization confirmation
- Target collection
- Target classification
- Pipeline initialization

Stage 0 supports both:

- Interactive dashboard execution
- Explicitly authorized non-interactive CLI execution

Non-interactive execution requires the caller to provide an explicit
authorization confirmation in the workflow context.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from scopeforgex.stages.shared import pipeline_paths
from scopeforgex.ui import (
    err,
    ok,
    stage,
    warn,
)


###############################################################################
# Target Detection
###############################################################################


def _is_cidr(
    value: str,
) -> bool:
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


def _is_ip(
    value: str,
) -> bool:
    """
    Detect a plain IP address.
    """

    try:
        ipaddress.ip_address(
            value
        )

        return True

    except ValueError:
        return False


def _is_ip_port(
    value: str,
) -> bool:
    """
    Detect IPv4:PORT targets.
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


def _is_url(
    value: str,
) -> bool:
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
    Classify the assessment target.

    Returns:
        "web" or "network"
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
    ctx: dict[str, Any],
) -> None:
    """
    Initialize canonical workflow pipeline paths.
    """

    ctx[
        "pipeline"
    ] = pipeline_paths(
        ctx["outdir"]
    )


###############################################################################
# Output Directory
###############################################################################


def _safe_target_name(
    target: str,
) -> str:
    """
    Convert a target into a filesystem-safe output directory component.
    """

    return (
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


def _set_target_context(
    ctx: dict[str, Any],
    target: str,
) -> None:
    """
    Populate target-derived workflow context.
    """

    target_type = classify_target(
        target
    )

    ctx[
        "target"
    ] = target

    ctx[
        "target_type"
    ] = target_type

    ctx[
        "outdir"
    ] = (
        f"outputs/"
        f"{_safe_target_name(target)}"
    )

    _initialize_pipeline(
        ctx
    )


###############################################################################
# Authorization / Target Collection
###############################################################################


def _collect_interactive_scope(
    ctx: dict[str, Any],
) -> str:
    """
    Collect authorization and target information interactively.
    """

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

    return target


def _collect_noninteractive_scope(
    ctx: dict[str, Any],
) -> str:
    """
    Validate explicitly supplied non-interactive scope.

    Non-interactive workflow execution is permitted only when the caller
    explicitly sets ``authorization_confirmed`` to True.
    """

    authorization_confirmed = ctx.get(
        "authorization_confirmed",
        False,
    )

    if authorization_confirmed is not True:
        raise RuntimeError(
            "Non-interactive execution requires explicit authorization "
            "confirmation."
        )

    target = str(
        ctx.get(
            "target",
            "",
        )
    ).strip()

    if not target:
        raise RuntimeError(
            "Non-interactive execution requires a target."
        )

    return target


###############################################################################
# Stage Entry
###############################################################################


def stage0_scope(
    ctx: dict[str, Any],
) -> None:
    """
    Validate scope and initialize workflow context.

    Interactive mode remains the default.

    Non-interactive mode is activated only when:

        ctx["non_interactive"] is True

    and requires:

        ctx["authorization_confirmed"] is True
        ctx["target"] contains a non-empty target
    """

    stage(
        "STAGE 0 — SCOPE & LEGAL CHECK",
        "blue",
    )

    non_interactive = (
        ctx.get(
            "non_interactive",
            False,
        )
        is True
    )

    if non_interactive:
        target = _collect_noninteractive_scope(
            ctx
        )

        ok(
            "Explicit authorization confirmed ✅"
        )

    else:
        target = _collect_interactive_scope(
            ctx
        )

    _set_target_context(
        ctx,
        target,
    )

    ok(
        f"Target set: {target}"
    )

    if ctx.get(
        "target_type"
    ) == "network":
        warn(
            "Network target detected. "
            "Web application discovery will be skipped."
        )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "classify_target",
    "stage0_scope",
]
