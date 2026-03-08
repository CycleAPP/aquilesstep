"""Interactive prompts and wizards for session setup."""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.panel import Panel
from rich.text import Text

from aquiles.ui.panels import info_panel, warning_panel

ASSESSMENT_TYPES = {
    1: {
        "key": "web",
        "name": "Web Application Assessment",
        "description": "Full-scope web app evaluation: recon, crawling, auth testing, API analysis.",
        "default_intensity": "medium",
    },
    2: {
        "key": "infrastructure",
        "name": "Internal Infrastructure Assessment",
        "description": "Network-level evaluation: host discovery, service enumeration, config review.",
        "default_intensity": "medium",
    },
    3: {
        "key": "active_directory",
        "name": "Active Directory Assessment",
        "description": "AD-focused: user enumeration, Kerberos attacks, GPO review, privilege paths.",
        "default_intensity": "medium",
    },
    4: {
        "key": "api",
        "name": "API Assessment",
        "description": "REST/GraphQL API testing: endpoint discovery, auth bypass, injection testing.",
        "default_intensity": "medium",
    },
    5: {
        "key": "bug_bounty",
        "name": "Bug Bounty Program",
        "description": "Scoped evaluation with BB-specific restrictions: no DoS, respect rate limits.",
        "default_intensity": "low",
    },
    6: {
        "key": "network_external",
        "name": "External Network Assessment",
        "description": "Perimeter evaluation: exposed services, misconfigurations, public attack surface.",
        "default_intensity": "medium",
    },
}

DISCLAIMER_TEXT = """
╔══════════════════════════════════════════════════════════════════════╗
║                    [!]  AUTHORIZATION AGREEMENT  [!]                  ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  By proceeding, you confirm and acknowledge:                         ║
║                                                                      ║
║  1. You have WRITTEN AUTHORIZATION to test all targets defined       ║
║     in the scope of this assessment.                                 ║
║                                                                      ║
║  2. You understand that unauthorized access to computer systems      ║
║     is ILLEGAL in most jurisdictions.                                ║
║                                                                      ║
║  3. You will NOT exceed the scope, intensity, or boundaries          ║
║     defined in this session.                                         ║
║                                                                      ║
║  4. You accept FULL RESPONSIBILITY for any actions performed         ║
║     using this tool.                                                 ║
║                                                                      ║
║  5. Aquiles does NOT exfiltrate data, connect to external servers    ║
║     (except AI API for analysis), or store data outside your         ║
║     local system.                                                    ║
║                                                                      ║
║  6. All scan results remain LOCAL on your machine.                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def select_assessment_type(console: Console | None = None) -> dict:
    """Prompt user to select an assessment type."""
    c = console or Console()

    c.print("\n[bold bright_white]Select Assessment Type:[/bold bright_white]\n")
    for num, at in ASSESSMENT_TYPES.items():
        c.print(f"  [bold bright_cyan]{num}.[/bold bright_cyan] [bold]{at['name']}[/bold]")
        c.print(f"     [dim]{at['description']}[/dim]")
    c.print()

    while True:
        choice = IntPrompt.ask(
            "[bold bright_yellow]>[/bold bright_yellow] Choose",
            console=c,
            default=1,
        )
        if choice in ASSESSMENT_TYPES:
            selected = ASSESSMENT_TYPES[choice]
            c.print(f"\n  [+] Selected: [bold bright_green]{selected['name']}[/bold bright_green]\n")
            return selected
        c.print("[red]  Invalid choice. Please select a number from the list.[/red]")


def define_scope(console: Console | None = None) -> dict:
    """Interactive scope definition wizard."""
    c = console or Console()

    info_panel(
        "*  Scope Definition",
        "Define the authorized targets and exclusions for this assessment.\n"
        "Separate multiple entries with commas.\n"
        "Leave blank to skip a category.",
        console=c,
    )

    domains = _ask_list("Domains (e.g., example.com, *.example.com)", c)
    ips = _ask_list("IP addresses / ranges (e.g., 10.0.0.1, 192.168.1.0/24)", c)
    urls = _ask_list("Specific URLs / endpoints (e.g., https://app.example.com/api)", c)
    ports = _ask_list("Port ranges (e.g., 80,443,8080-8090) [blank = all common]", c)
    exclusions = _ask_list("Exclusions (hosts, paths, or IPs to AVOID)", c)

    scope = {
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "ports": ports if ports else ["1-65535"],
        "exclusions": exclusions,
    }

    if not domains and not ips and not urls:
        warning_panel("No Targets", "You haven't defined any targets. At least one target is required.", console=c)
        return define_scope(console=c)

    return scope


def show_disclaimer_and_confirm(console: Console | None = None) -> bool:
    """Show legal disclaimer and require explicit acceptance."""
    c = console or Console()
    c.print(Panel(DISCLAIMER_TEXT, border_style="bright_red", padding=(0, 1)))

    accepted = Confirm.ask(
        "\n[bold bright_yellow]Do you ACCEPT these terms and confirm you have authorization?[/bold bright_yellow]",
        console=c,
        default=False,
    )

    if accepted:
        c.print("\n  [bold green][+] Authorization accepted. Proceeding...[/bold green]\n")
    else:
        c.print("\n  [bold red][-] Authorization declined. Aquiles will not proceed.[/bold red]\n")

    return accepted


def ask_objective(console: Console | None = None) -> str:
    """Ask the auditor for a brief technical objective description."""
    c = console or Console()

    info_panel(
        "*  Assessment Objective",
        "Describe what you want to evaluate. Be specific about:\n"
        "• Technologies you know about (frameworks, APIs, auth methods)\n"
        "• Areas of interest or suspicion\n"
        "• Any hints or prior knowledge\n\n"
        "[dim]Example: 'Web app with JWT auth and REST API. API might be weakest point.'[/dim]",
        console=c,
    )

    objective = Prompt.ask("[bold bright_yellow]>[/bold bright_yellow] Your objective", console=c)
    return objective.strip()


def confirm_plan(console: Console | None = None) -> str:
    """Ask auditor to confirm, modify, or abort the plan."""
    c = console or Console()
    c.print()
    choice = Prompt.ask(
        "[bold bright_yellow]>[/bold bright_yellow] [bold]Accept[/bold] / [bold]Modify[/bold] / [bold]Abort[/bold]",
        choices=["accept", "modify", "abort", "a", "m", "x"],
        default="accept",
        console=c,
    )
    return {"a": "accept", "m": "modify", "x": "abort"}.get(choice, choice)


def ask_phase_action(phase_name: str, has_failures: bool = False, console: Console | None = None) -> str:
    """Ask auditor what to do after a phase completes — expanded menu."""
    c = console or Console()
    c.print()

    options = "[bold]Continue[/bold] / [bold]Hint[/bold] / [bold]Reprioritize[/bold]"
    choices = ["continue", "hint", "reprioritize", "skip", "stop", "c", "h", "r", "s", "x"]

    if has_failures:
        options += " / [bold yellow]Retry failed[/bold yellow]"
        choices.append("retry")
        choices.append("t")

    options += " / [bold]Skip next[/bold] / [bold]Stop[/bold]"

    choice = Prompt.ask(
        f"[bold bright_yellow]>[/bold bright_yellow] Phase '[bold]{phase_name}[/bold]' complete.\n"
        f"  {options}",
        choices=choices,
        default="continue",
        console=c,
    )
    alias_map = {"c": "continue", "h": "hint", "r": "reprioritize", "s": "skip", "x": "stop", "t": "retry"}
    return alias_map.get(choice, choice)


def ask_pre_phase_hint(phase_name: str, console: Console | None = None) -> str | None:
    """Ask the auditor for hints before a phase starts."""
    c = console or Console()
    raw = Prompt.ask(
        f"  [dim]Any hints for[/dim] [bold]{phase_name}[/bold][dim]? (Enter to skip)[/dim]",
        default="",
        console=c,
    )
    return raw.strip() or None


def ask_hint_details(console: Console | None = None) -> dict:
    """Collect structured hint from the auditor."""
    c = console or Console()
    c.print("\n[bold bright_white]Add a Hint[/bold bright_white]")
    c.print("  [dim]Types: focus, skip, add_tool, context[/dim]")

    hint_type = Prompt.ask(
        "  [bold bright_yellow]>[/bold bright_yellow] Type",
        choices=["focus", "skip", "add_tool", "context"],
        default="context",
        console=c,
    )

    text = Prompt.ask(
        "  [bold bright_yellow]>[/bold bright_yellow] Hint",
        console=c,
    ).strip()

    priority = Prompt.ask(
        "  [bold bright_yellow]>[/bold bright_yellow] Priority",
        choices=["critical", "high", "normal"],
        default="normal",
        console=c,
    )

    return {"text": text, "hint_type": hint_type, "priority": priority}


def ask_retry_failed(failed_tools: list[str], console: Console | None = None) -> str:
    """Ask auditor whether to retry failed tools."""
    c = console or Console()
    c.print(f"\n  [yellow][!] {len(failed_tools)} tool(s) failed:[/yellow]")
    for t in failed_tools:
        c.print(f"    [dim]• {t}[/dim]")

    choice = Prompt.ask(
        "  [bold bright_yellow]>[/bold bright_yellow] [bold]Retry[/bold] / [bold]Skip[/bold] / [bold]Stop[/bold]",
        choices=["retry", "skip", "stop", "r", "s", "x"],
        default="skip",
        console=c,
    )
    return {"r": "retry", "s": "skip", "x": "stop"}.get(choice, choice)


def ask_reprioritize(phase_names: list[str], console: Console | None = None) -> dict:
    """Let auditor reorder or inject phases."""
    c = console or Console()
    c.print("\n[bold bright_white]Reprioritize Remaining Phases:[/bold bright_white]")
    for i, name in enumerate(phase_names, 1):
        c.print(f"  [dim]{i}.[/dim] {name}")

    c.print("\n  [dim]Options:[/dim]")
    c.print("  [dim]• Enter new order (e.g. '3,1,2')[/dim]")
    c.print("  [dim]• Type 'inject <name>' to add a new phase[/dim]")
    c.print("  [dim]• Press Enter to keep current order[/dim]")

    raw = Prompt.ask(
        "  [bold bright_yellow]>[/bold bright_yellow] New order",
        default="",
        console=c,
    ).strip()

    if not raw:
        return {"action": "keep"}
    if raw.lower().startswith("inject "):
        return {"action": "inject", "phase_name": raw[7:].strip()}

    # Parse numeric order
    try:
        indices = [int(x.strip()) - 1 for x in raw.split(",")]
        return {"action": "reorder", "indices": indices}
    except ValueError:
        c.print("  [dim red]Invalid input, keeping current order.[/dim red]")
        return {"action": "keep"}


def ask_modification(console: Console | None = None) -> str:
    """Ask auditor for plan modifications."""
    c = console or Console()
    return Prompt.ask(
        "[bold bright_yellow]>[/bold bright_yellow] Describe your modifications or additional hints",
        console=c,
    ).strip()


def ask_intensity(default: str = "medium", console: Console | None = None) -> str:
    """Ask for scan intensity level."""
    c = console or Console()
    c.print("\n[bold bright_white]Scan Intensity:[/bold bright_white]")
    c.print("  [green]low[/green]      — Passive / minimal traffic (good for bug bounty)")
    c.print("  [yellow]medium[/yellow]   — Standard scanning (balanced)")
    c.print("  [red]high[/red]     — Aggressive scanning (internal/authorized only)")
    c.print()

    return Prompt.ask(
        "[bold bright_yellow]>[/bold bright_yellow] Intensity",
        choices=["low", "medium", "high"],
        default=default,
        console=c,
    )


def _ask_list(label: str, console: Console) -> list[str]:
    """Prompt for a comma-separated list."""
    raw = Prompt.ask(f"  [bold bright_white]{label}[/bold bright_white]", default="", console=console)
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
