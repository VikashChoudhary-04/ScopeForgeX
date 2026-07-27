"""
ScopeForgeX Dashboard
=====================

Interactive dashboard for launching workflows,
installing tools, and viewing previous runs.

v0.5.2
"""

from __future__ import annotations

import questionary

from scopeforgex.installer import install_tools
from scopeforgex.state import load_last_run
from scopeforgex.ui import ok, stage, summary_table, warn
from scopeforgex.workflow import run_profile


_MENU_ACTIONS = {
    "Run FAST Profile": lambda: run_profile("fast"),
    "Run FULL_SAFE Profile": lambda: run_profile("full_safe"),
    "Install Tools": install_tools,
}


def _show_last_run():
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


def dashboard():
    """
    Launch the interactive ScopeForgeX dashboard.

    Executes one selected action and exits cleanly
    after workflow completion.
    """

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

    if action is not None:

        action()

        ok(
            "ScopeForgeX session finished ✅"
        )
