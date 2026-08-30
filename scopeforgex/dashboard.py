"""
ScopeForgeX Dashboard
=====================

Interactive dashboard for launching workflows,
installing tools, and viewing previous runs.

The dashboard requires an interactive terminal because the menu is built with
Questionary. Non-interactive invocation is rejected instead of implicitly
selecting the first menu action.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import sys

import questionary

from scopeforgex.installer import install_tools
from scopeforgex.state import load_last_run
from scopeforgex.ui import err, ok, stage, summary_table, warn
from scopeforgex.workflow import run_profile


###############################################################################
# Menu Actions
###############################################################################


_MENU_ACTIONS = {
    "Run FAST Profile": lambda: run_profile("fast"),
    "Run STANDARD Profile": lambda: run_profile("standard"),
    "Run FULL Profile": lambda: run_profile("full"),
    "Install Tools": install_tools,
}


###############################################################################
# Last Run
###############################################################################


def _show_last_run() -> None:
    """
    Display information about the most recent workflow.
    """

    last = load_last_run()

    if not last:
        warn(
            "No previous run found."
        )
        return

    ok(
        "Loaded last run ✅"
    )

    summary_table(
        "Last Run",
        [
            (
                "Target Type",
                str(
                    last.get(
                        "target_type",
                        "-",
                    )
                ),
            ),
            (
                "Target",
                str(
                    last.get(
                        "target",
                        "-",
                    )
                ),
            ),
            (
                "Output Directory",
                str(
                    last.get(
                        "outdir",
                        "-",
                    )
                ),
            ),
        ],
    )


###############################################################################
# Interactive Terminal Guard
###############################################################################


def _require_interactive_terminal() -> bool:
    """
    Ensure the dashboard is running with an interactive stdin.

    Questionary cannot safely consume menu selections from a redirected
    or piped stdin. Rather than silently choosing the first menu item, the
    dashboard exits cleanly and tells the operator what is required.
    """

    if sys.stdin.isatty():
        return True

    err(
        "ScopeForgeX dashboard requires an interactive terminal."
    )

    warn(
        "Do not pipe stdin into 'python -m scopeforgex'."
    )

    return False


###############################################################################
# Dashboard
###############################################################################


def dashboard() -> None:
    """
    Launch the interactive ScopeForgeX dashboard.

    Executes one selected action and exits cleanly
    after workflow completion.
    """

    if not _require_interactive_terminal():
        return

    stage(
        "ScopeForgeX Dashboard",
        "green",
    )

    choice = questionary.select(
        "Choose an action:",
        choices=[
            *list(
                _MENU_ACTIONS.keys()
            ),
            "View Last Run",
            "Exit",
        ],
    ).ask()

    if choice is None:
        warn(
            "No dashboard action selected."
        )
        return

    if choice == "Exit":
        ok(
            "Goodbye ✅"
        )
        return

    if choice == "View Last Run":
        _show_last_run()
        return

    action = _MENU_ACTIONS.get(
        choice
    )

    if action is None:
        warn(
            f"Unknown dashboard action: {choice}"
        )
        return

    action()

    ok(
        "ScopeForgeX session finished ✅"
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "dashboard",
]
