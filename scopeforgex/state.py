"""
ScopeForgeX State Management
============================

Helpers for persisting and restoring the most recent workflow
execution.

v0.5.0
"""

from __future__ import annotations

import json
from pathlib import Path


STATE_FILE = Path("outputs") / ".last_run.json"


def save_last_run(
    ctx: dict,
):
    """
    Save the most recent workflow context.

    Supports both legacy workflow context and
    RuntimeState-backed execution.
    """

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    runtime = ctx.get(
        "runtime_state"
    )

    data = {
        "target_type": (
            ctx.get("target_type")
            or getattr(
                runtime,
                "target_type",
                None,
            )
        ),

        "target": (
            ctx.get("target")
            or getattr(
                runtime,
                "target",
                None,
            )
        ),

        "outdir": (
            ctx.get("outdir")
        ),
    }

    with STATE_FILE.open(
        "w",
        encoding="utf-8",
    ) as outfile:

        json.dump(
            data,
            outfile,
            indent=2,
        )


def load_last_run() -> dict | None:
    """
    Load the previous workflow state.
    """

    if not STATE_FILE.exists():
        return None

    try:

        with STATE_FILE.open(
            "r",
            encoding="utf-8",
        ) as infile:

            data = json.load(
                infile
            )

        return (
            data
            if isinstance(data, dict)
            else None
        )

    except (
        OSError,
        json.JSONDecodeError,
    ):

        return None


__all__ = [
    "save_last_run",
    "load_last_run",
]
