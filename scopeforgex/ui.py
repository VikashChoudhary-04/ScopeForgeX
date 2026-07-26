"""
ScopeForgeX User Interface
==========================

Rich-based console helpers used throughout ScopeForgeX.

Provides consistent banners, stage headers, status messages,
and summary tables.

v0.4.0
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


# ----------------------------------------------------------------------
# Internal helpers
# ----------------------------------------------------------------------

def _status(icon: str, color: str, message: str):
    """
    Print a standardized status message.
    """

    console.print(f"[{color}][{icon}][/{color}] {message}")


# ----------------------------------------------------------------------
# Public UI
# ----------------------------------------------------------------------

def banner():
    """
    Display the ScopeForgeX startup banner.
    """

    title = Text("ScopeForgeX", style="bold green")
    subtitle = Text(
        "CLI-only Workflow Automation (Safe Mode)",
        style="cyan",
    )

    console.print(
        Panel.fit(
            Text.assemble(title, "\n", subtitle),
            border_style="green",
        )
    )


def stage(title: str, color: str = "blue"):
    """
    Display a stage header.
    """

    console.print()

    console.print(
        Panel.fit(
            f"[bold {color}]{title}[/bold {color}]",
            border_style=color,
        )
    )


def info(message: str):
    """
    Display an informational message.
    """

    _status("*", "cyan", message)


def ok(message: str):
    """
    Display a success message.
    """

    _status("✔", "green", message)


def warn(message: str):
    """
    Display a warning message.
    """

    _status("!", "yellow", message)


def err(message: str):
    """
    Display an error message.
    """

    _status("✘", "red", message)


def summary_table(
    title: str,
    rows: list[tuple[str, str]],
):
    """
    Display a two-column summary table.
    """

    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
    )

    table.add_column(
        "Item",
        style="bold",
    )

    table.add_column(
        "Value",
        overflow="fold",
    )

    for key, value in rows:
        table.add_row(
            str(key),
            str(value),
        )

    console.print(table)
