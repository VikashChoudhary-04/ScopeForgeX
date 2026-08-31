"""
ScopeForgeX Command-Line Interface
===================================

Application entry point.

The CLI supports two modes:

1. No execution arguments:
   Launch the interactive dashboard.

2. Explicit target execution:
   Execute an existing WorkflowEngine profile non-interactively.

Non-interactive execution requires an explicit ``--authorized`` flag.

Examples:

    python -m scopeforgex

    python -m scopeforgex \
        --profile standard \
        --target example.com \
        --authorized

    python -m scopeforgex \
        --profile fast \
        --target example.com \
        --authorized

    python -m scopeforgex \
        --profile full \
        --target example.com \
        --authorized

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import argparse
import sys

from scopeforgex.config import SUPPORTED_PROFILES
from scopeforgex.dashboard import dashboard
from scopeforgex.state import save_last_run
from scopeforgex.ui import (
    banner,
    info,
    ok,
    summary_table,
    warn,
)
from scopeforgex.workflow import WorkflowEngine


###############################################################################
# Argument Parser
###############################################################################


def _build_parser() -> argparse.ArgumentParser:
    """
    Build the ScopeForgeX command-line argument parser.
    """

    parser = argparse.ArgumentParser(
        prog="scopeforgex",
        description=(
            "CLI-only ethical hacking workflow automation for "
            "authorized security assessments."
        ),
        epilog=(
            "Use only against systems you own or are explicitly "
            "authorized to test."
        ),
    )

    parser.add_argument(
        "--profile",
        choices=SUPPORTED_PROFILES,
        default="standard",
        help=(
            "Assessment profile used for non-interactive execution. "
            "Defaults to standard."
        ),
    )

    parser.add_argument(
        "--target",
        help=(
            "Assessment target for non-interactive execution."
        ),
    )

    parser.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "Explicitly confirm that you have written authorization "
            "to assess the supplied target."
        ),
    )

    return parser


###############################################################################
# Non-Interactive Validation
###############################################################################


def _validate_noninteractive_arguments(
    args: argparse.Namespace,
) -> bool:
    """
    Validate CLI arguments and determine execution mode.

    Returns:
        True when non-interactive workflow execution was requested.
        False when the interactive dashboard should be launched.
    """

    target_supplied = (
        args.target is not None
    )

    authorized_supplied = (
        args.authorized is True
    )

    # No target and no authorization flag means normal dashboard mode.
    if not target_supplied and not authorized_supplied:
        return False

    if not target_supplied:
        raise SystemExit(
            "--authorized requires --target."
        )

    if not authorized_supplied:
        raise SystemExit(
            "--target requires explicit --authorized confirmation."
        )

    target = str(
        args.target
    ).strip()

    if not target:
        raise SystemExit(
            "--target cannot be empty."
        )

    return True


###############################################################################
# Non-Interactive Execution
###############################################################################


def _run_noninteractive(
    args: argparse.Namespace,
) -> dict:
    """
    Execute the existing WorkflowEngine in explicit CLI mode.

    No second workflow implementation is introduced. The CLI simply
    pre-populates the context consumed by Stage 0.
    """

    engine = WorkflowEngine(
        args.profile
    )

    engine.ctx.update(
        {
            "non_interactive": True,
            "authorization_confirmed": True,
            "target": str(
                args.target
            ).strip(),
        }
    )

    ctx = engine.run()

    try:
        save_last_run(
            ctx
        )

    except Exception as exc:
        warn(
            f"Could not persist last-run state: {exc}"
        )

    ok(
        "Workflow completed ✅"
    )

    summary_table(
        "ScopeForgeX Summary",
        [
            (
                "Profile",
                args.profile,
            ),
            (
                "Target Type",
                ctx.get(
                    "target_type",
                    "-",
                ),
            ),
            (
                "Target",
                ctx.get(
                    "target",
                    "-",
                ),
            ),
            (
                "Tools Executed",
                len(
                    engine.selected_tools
                ),
            ),
            (
                "Output Directory",
                ctx.get(
                    "outdir",
                    "-",
                ),
            ),
        ],
    )

    return ctx


###############################################################################
# Main
###############################################################################


def main() -> None:
    """
    Launch the ScopeForgeX CLI.
    """

    parser = _build_parser()
    args = parser.parse_args()

    banner()

    info(
        "CLI-only Ethical Hacking Workflow Automation"
    )

    info(
        "Authorized testing only ✅"
    )

    info(
        "Use only against systems you own or are explicitly authorized to test."
    )

    info("")

    noninteractive = (
        _validate_noninteractive_arguments(
            args
        )
    )

    if noninteractive:
        _run_noninteractive(
            args
        )
        return

    dashboard()


###############################################################################
# Module Entry Point
###############################################################################


if __name__ == "__main__":
    main()
