"""
ScopeForgeX State Management
============================

Helpers for persisting and restoring the most recent workflow
execution.

v0.4.0
"""

from __future__ import annotations

import json
from pathlib import Path

STATE_FILE = Path("outputs") / ".last_run.json"


def save_last_run(ctx: dict):
    """
    Save the most recent workflow context.

    Only the minimal information required for future operations
    is persisted.
    """

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "target_type": ctx.get("target_type"),
        "target": ctx.get("target"),
        "outdir": ctx.get("outdir"),
    }

    with STATE_FILE.open("w", encoding="utf-8") as outfile:
        json.dump(data, outfile, indent=2)


def load_last_run() -> dict | None:
    """
    Load the previously saved workflow state.

    Returns:
        Dictionary containing the saved state,
        or None if unavailable.
    """

    if not STATE_FILE.exists():
        return None

    try:
        with STATE_FILE.open("r", encoding="utf-8") as infile:
            data = json.load(infile)

        return data if isinstance(data, dict) else None

    except (OSError, json.JSONDecodeError):
        return None
