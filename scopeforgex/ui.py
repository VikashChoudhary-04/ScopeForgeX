from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

console = Console()

def banner():
    title = Text("ScopeForgeX", style="bold green")
    subtitle = Text("CLI-only Workflow Automation (Safe Mode)", style="cyan")
    console.print(Panel.fit(Text.assemble(title, "\n", subtitle), border_style="green"))

def stage(title: str, color: str = "blue"):
    console.print()
    console.print(Panel.fit(f"[bold {color}]{title}[/bold {color}]", border_style=color))

def info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")

def ok(msg: str):
    console.print(f"[green][✔][/green] {msg}")

def warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")

def err(msg: str):
    console.print(f"[red][✘][/red] {msg}")

def summary_table(title: str, rows: list[tuple[str, str]]):
    table = Table(title=title, show_header=True, header_style="bold magenta")
    table.add_column("Item", style="bold")
    table.add_column("Value", overflow="fold")
    for k, v in rows:
        table.add_row(k, v)
    console.print(table)
