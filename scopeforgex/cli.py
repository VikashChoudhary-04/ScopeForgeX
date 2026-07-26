"""
ScopeForgeX Command-Line Interface
=================================

Application entry point.

Initializes the user interface and launches the interactive
dashboard.

v0.4.0
"""

from __future__ import annotations

from scopeforgex.dashboard import dashboard
from scopeforgex.ui import banner, info


def main():
    """
    Launch the ScopeForgeX CLI.
    """

    banner()

    info("CLI-only Ethical Hacking Workflow Automation")
    info("Authorized testing only ✅")
    info("Use only against systems you own or are explicitly authorized to test.")
    info("")

    dashboard()


if __name__ == "__main__":
    main()
