"""
ScopeForgeX State Management
============================

Persistence helpers for the most recent ScopeForgeX workflow execution.

The persisted state contains a JSON-safe summary of the completed workflow,
including profile, target, execution results, stage results, timing, and
output directory.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


###############################################################################
# Constants
###############################################################################


STATE_FILE = Path(
    "outputs"
) / ".last_run.json"


###############################################################################
# JSON Serialization Helpers
###############################################################################


def _serialize(
    value: Any,
) -> Any:
    """
    Convert a ScopeForgeX runtime value into JSON-safe data.

    Objects exposing ``as_dict()`` are serialized through that public API.
    Dataclasses and enum values are handled explicitly. Mappings and
    sequences are recursively converted.
    """

    if value is None:
        return None

    if isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if isinstance(
        value,
        Enum,
    ):
        return value.value

    if isinstance(
        value,
        datetime,
    ):
        return value.isoformat()

    as_dict = getattr(
        value,
        "as_dict",
        None,
    )

    if callable(
        as_dict
    ):
        try:
            return _serialize(
                as_dict()
            )
        except Exception:
            pass

    if isinstance(
        value,
        Mapping,
    ):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return [
            _serialize(item)
            for item in value
        ]

    if hasattr(
        value,
        "__dict__",
    ):
        try:
            return {
                str(key): _serialize(item)
                for key, item in vars(value).items()
            }
        except Exception:
            pass

    return str(
        value
    )


###############################################################################
# State Construction
###############################################################################


def _runtime_from_context(
    ctx: Mapping[str, Any],
) -> Any | None:
    """
    Resolve the canonical RuntimeState from workflow context.

    ``runtime`` is the current key used by WorkflowEngine. The older
    ``runtime_state`` key is accepted only as a harmless compatibility
    fallback.
    """

    runtime = ctx.get(
        "runtime"
    )

    if runtime is not None:
        return runtime

    return ctx.get(
        "runtime_state"
    )


def _build_state(
    ctx: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Build the JSON-safe persisted workflow state.
    """

    runtime = _runtime_from_context(
        ctx
    )

    execution_results = ctx.get(
        "execution_results",
        [],
    )

    stage_results = ctx.get(
        "stage_results",
        [],
    )

    if not isinstance(
        execution_results,
        (list, tuple),
    ):
        execution_results = []

    if not isinstance(
        stage_results,
        (list, tuple),
    ):
        stage_results = []

    target = (
        ctx.get(
            "target"
        )
        or getattr(
            runtime,
            "target",
            None,
        )
    )

    target_type = (
        ctx.get(
            "target_type"
        )
        or getattr(
            runtime,
            "target_type",
            None,
        )
    )

    profile = (
        ctx.get(
            "profile"
        )
        or getattr(
            runtime,
            "profile",
            None,
        )
    )

    outdir = ctx.get(
        "outdir"
    )

    start_time = ctx.get(
        "workflow_start_time"
    )

    end_time = ctx.get(
        "workflow_end_time"
    )

    duration = ctx.get(
        "workflow_duration"
    )

    return {
        "profile": _serialize(
            profile
        ),
        "target_type": _serialize(
            target_type
        ),
        "target": _serialize(
            target
        ),
        "outdir": _serialize(
            outdir
        ),
        "workflow_start_time": _serialize(
            start_time
        ),
        "workflow_end_time": _serialize(
            end_time
        ),
        "workflow_duration": _serialize(
            duration
        ),
        "execution_results": _serialize(
            execution_results
        ),
        "stage_results": _serialize(
            stage_results
        ),
    }


###############################################################################
# Public Persistence API
###############################################################################


def save_last_run(
    ctx: dict,
) -> None:
    """
    Save the most recent ScopeForgeX workflow state.

    The persisted representation is deliberately JSON-safe and contains
    enough information for the dashboard's last-run view and subsequent
    diagnostics.
    """

    if not isinstance(
        ctx,
        dict,
    ):
        raise TypeError(
            "save_last_run() requires a workflow context dictionary."
        )

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = _build_state(
        ctx
    )

    with STATE_FILE.open(
        "w",
        encoding="utf-8",
    ) as outfile:
        json.dump(
            data,
            outfile,
            indent=2,
            ensure_ascii=False,
        )


def load_last_run() -> dict | None:
    """
    Load the previous persisted workflow state.

    Returns:
        A dictionary when valid state exists, otherwise ``None``.
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
            if isinstance(
                data,
                dict,
            )
            else None
        )

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None


###############################################################################
# Public API
###############################################################################


__all__ = [
    "STATE_FILE",
    "save_last_run",
    "load_last_run",
]
