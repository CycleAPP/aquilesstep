"""Rich-based UI panels, tables and display components."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.markdown import Markdown


def info_panel(title: str, body: str, style: str = "cyan", console: Console | None = None) -> None:
    """Show an informational panel."""
    c = console or Console()
    c.print(Panel(body, title=f"[bold]{title}[/bold]", border_style=style, padding=(1, 2)))


def warning_panel(title: str, body: str, console: Console | None = None) -> None:
    """Show a warning panel."""
    info_panel(f"[!]  {title}", body, style="yellow", console=console)


def error_panel(title: str, body: str, console: Console | None = None) -> None:
    """Show an error panel."""
    info_panel(f"[-] {title}", body, style="red", console=console)


def success_panel(title: str, body: str, console: Console | None = None) -> None:
    """Show a success panel."""
    info_panel(f"[+] {title}", body, style="green", console=console)


def phase_header(phase_num: int, name: str, console: Console | None = None) -> None:
    """Display a phase header."""
    c = console or Console()
    c.print()
    c.print(Rule(f"[bold bright_yellow]Phase {phase_num}: {name}[/bold bright_yellow]", style="bright_yellow"))
    c.print()


def findings_table(
    findings: list[dict],
    title: str = "Findings",
    console: Console | None = None,
) -> None:
    """Render a table of findings."""
    c = console or Console()
    table = Table(title=title, border_style="bright_cyan", show_lines=True, expand=True)
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=16)
    table.add_column("Finding", ratio=2)
    table.add_column("Target", width=30)

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim white",
    }

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "info").lower()
        color = severity_colors.get(sev, "white")
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            f.get("category", "—"),
            f.get("description", "—"),
            f.get("target", "—"),
        )

    c.print(table)


def plan_tree(phases: list[dict], console: Console | None = None) -> None:
    """Render the assessment plan as a tree."""
    c = console or Console()
    tree = Tree("📋 [bold bright_white]Assessment Plan[/bold bright_white]", guide_style="bright_cyan")

    for i, phase in enumerate(phases, 1):
        status_icon = {"pending": "~", "running": ">", "done": "[+]", "skipped": ">>"}.get(
            phase.get("status", "pending"), "~"
        )
        branch = tree.add(f"{status_icon} [bold]Phase {i}:[/bold] {phase.get('name', 'Unknown')}")
        for tool_name in phase.get("tools", []):
            branch.add(f"[dim]→ {tool_name}[/dim]")

    c.print(Panel(tree, border_style="bright_cyan", padding=(1, 2)))


def tool_progress(console: Console | None = None) -> Progress:
    """Create a progress bar for tool execution."""
    c = console or Console()
    return Progress(
        SpinnerColumn("dots", style="bright_cyan"),
        TextColumn("[bold bright_white]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="bright_green"),
        TextColumn("[dim]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=c,
    )


def scope_summary(
    targets: list[str],
    exclusions: list[str],
    assessment_type: str,
    console: Console | None = None,
) -> None:
    """Display scope summary."""
    c = console or Console()

    target_list = "\n".join(f"  [green]v[/green] {t}" for t in targets) if targets else "  [dim]None defined[/dim]"
    exclusion_list = "\n".join(f"  [red]x[/red] {e}" for e in exclusions) if exclusions else "  [dim]None defined[/dim]"

    body = (
        f"[bold]Assessment Type:[/bold] [bright_cyan]{assessment_type}[/bright_cyan]\n\n"
        f"[bold]Authorized Targets:[/bold]\n{target_list}\n\n"
        f"[bold]Exclusions:[/bold]\n{exclusion_list}"
    )

    c.print(Panel(body, title="[bold]*  Scope Summary[/bold]", border_style="bright_cyan", padding=(1, 2)))


def render_markdown(text: str, console: Console | None = None) -> None:
    """Render markdown text."""
    c = console or Console()
    c.print(Markdown(text))


def section_divider(title: str = "", console: Console | None = None) -> None:
    """Print a section divider."""
    c = console or Console()
    if title:
        c.print(Rule(f"[bold]{title}[/bold]", style="bright_blue"))
    else:
        c.print(Rule(style="dim"))
