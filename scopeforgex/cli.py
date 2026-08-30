"""
ScopeForgeX Command-Line Interface
===================================

Application entry point.

Provides lightweight command-line argument handling while preserving
the interactive dashboard as the default interface.

v1.0.0
"""

from __future__ import annotations

import argparse

from scopeforgex.dashboard import dashboard
from scopeforgex.ui import banner, info


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

    return parser


###############################################################################
# Main
###############################################################################


def main() -> None:
    """
    Launch the ScopeForgeX CLI.
    """

    parser = _build_parser()

    # argparse handles --help / -h and exits before the dashboard.
    parser.parse_args()

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

    dashboard()


###############################################################################
# Module Entry Point
###############################################################################


if __name__ == "__main__":
    main()
