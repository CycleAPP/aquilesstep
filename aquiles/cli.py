"""Main CLI interface for Aquiles — the interactive orchestration loop.

Provides three commands:
- `aquiles start`    — Start a new assessment session
- `aquiles resume`   — Resume a previous session
- `aquiles sessions` — List saved sessions
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from aquiles.ui.banner import show_banner
from aquiles.ui.panels import (
    info_panel, warning_panel, error_panel, success_panel,
    phase_header, findings_table, plan_tree, scope_summary,
    tool_progress, section_divider, render_markdown,
)
from aquiles.ui.prompts import (
    select_assessment_type, define_scope, show_disclaimer_and_confirm,
    ask_objective, confirm_plan, ask_phase_action, ask_modification,
    ask_intensity, ask_pre_phase_hint, ask_hint_details,
    ask_retry_failed, ask_reprioritize,
)
from aquiles.core.session import Session, Finding, ExecutionState
from aquiles.core.policy import PolicyEngine
from aquiles.core.planner import Planner
from aquiles.core.executor import Executor
from aquiles.core.analyzer import Analyzer
from aquiles.core.reporter import Reporter
from aquiles.core.hints import HintEngine, HintType
from aquiles.core.errors import classify_error, ErrorSeverity
from aquiles.catalog.loader import (
    load_all_tools, get_tools_by_assessment_type,
    find_tools_by_prefix, get_tool_summary,
)


console = Console()


@click.group()
def cli():
    """Aquiles — AI-Assisted Pentesting Orchestrator."""
    pass


# ═══════════════════════════════════════════
#  aquiles start
# ═══════════════════════════════════════════

@cli.command()
@click.option("--workspace", "-w", default=None, help="Workspace directory for session outputs")
def start(workspace: str | None):
    """Start an interactive Aquiles assessment session."""
    try:
        _run_interactive_session(workspace)
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Session interrupted by user.[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        error_panel("Fatal Error", str(e), console=console)
        raise


# ═══════════════════════════════════════════
#  aquiles resume
# ═══════════════════════════════════════════

@cli.command()
@click.argument("session_dir")
def resume(session_dir: str):
    """Resume a previously saved Aquiles session."""
    try:
        _resume_session(session_dir)
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow][!] Session interrupted by user.[/bold yellow]")
        sys.exit(0)
    except FileNotFoundError as e:
        error_panel("Session Not Found", str(e), console=console)
        sys.exit(1)
    except Exception as e:
        error_panel("Fatal Error", str(e), console=console)
        raise


# ═══════════════════════════════════════════
#  aquiles sessions
# ═══════════════════════════════════════════

@cli.command()
@click.option("--dir", "-d", "search_dir", default=None, help="Directory to search for sessions")
def sessions(search_dir: str | None):
    """List saved Aquiles sessions."""
    show_banner(console)
    saved = Session.list_sessions(search_dir)
    if not saved:
        console.print("[dim]No saved sessions found.[/dim]")
        return

    table = Table(title="Saved Sessions", border_style="bright_cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Session ID", style="bright_cyan")
    table.add_column("Type", style="bright_white")
    table.add_column("State", style="yellow")
    table.add_column("Progress", style="green")
    table.add_column("Findings", style="bright_red")
    table.add_column("Path", style="dim")

    for i, s in enumerate(saved, 1):
        state_colors = {"executing": "yellow", "paused": "bright_yellow", "completed": "green", "failed": "red"}
        state_style = state_colors.get(s["state"], "dim")
        table.add_row(
            str(i),
            s["session_id"],
            s["assessment_type"],
            f"[{state_style}]{s['state']}[/{state_style}]",
            f"{s['phases_done']}/{s['phases_total']}",
            str(s["findings_count"]),
            s["path"],
        )

    console.print(table)
    console.print("\n[dim]To resume: aquiles resume <path>[/dim]")


# ═══════════════════════════════════════════
#  Interactive Session (new)
# ═══════════════════════════════════════════

def _run_interactive_session(workspace: str | None) -> None:
    """Main interactive session flow."""

    # ── Step 1: Banner ──
    show_banner(console)

    # ── Step 2: Load Tool Catalog ──
    console.print("[dim]Loading tool catalog...[/dim]")
    all_tools = load_all_tools()
    tool_stats = get_tool_summary(all_tools)
    total_tools = sum(tool_stats.values())
    console.print(f"[green]v[/green] Loaded [bold]{total_tools}[/bold] tools across [bold]{len(tool_stats)}[/bold] categories\n")

    for cat, count in sorted(tool_stats.items()):
        console.print(f"  [dim]•[/dim] {cat}: [bright_cyan]{count}[/bright_cyan] tools")

    # Show AI provider status
    from aquiles.core.ai_provider import get_ai_config
    ai_config = get_ai_config()
    if ai_config.available:
        console.print(f"\n  [green]🤖 AI:[/green] [bold]{ai_config.provider}[/bold] ({ai_config.model})")
    else:
        console.print(f"\n  [dim yellow]🤖 AI: No API key detected. Set DEEPSEEK_API_KEY or OPENAI_API_KEY for AI features.[/dim yellow]")
    console.print()

    # ── Step 3: Select Assessment Type ──
    section_divider("Assessment Configuration", console=console)
    assessment_type = select_assessment_type(console)

    # ── Step 4: Define Scope ──
    scope = define_scope(console)

    # ── Step 5: Select Intensity ──
    intensity = ask_intensity(
        default=assessment_type.get("default_intensity", "medium"),
        console=console,
    )

    # ── Step 6: Authorization ──
    section_divider("Authorization", console=console)
    if not show_disclaimer_and_confirm(console):
        console.print("[bold red]Session aborted. Authorization declined.[/bold red]")
        return

    # ── Step 7: Create Session + Hint Engine ──
    session = Session(workspace_dir=workspace)
    session.assessment_type = assessment_type
    session.scope = scope
    session.intensity = intensity
    session.authorization_accepted = True
    session.set_state(ExecutionState.SETUP)

    hint_engine = HintEngine()

    # ── Step 8: Create Policy Engine ──
    policy = PolicyEngine(
        domains=scope["domains"],
        ips=scope["ips"],
        urls=scope["urls"],
        ports=scope["ports"],
        exclusions=scope["exclusions"],
        intensity=intensity,
        assessment_type=assessment_type["key"],
    )

    # ── Step 9: Show Scope Summary ──
    scope_summary(
        targets=session.targets,
        exclusions=session.exclusions,
        assessment_type=assessment_type["name"],
        console=console,
    )

    # ── Step 10: Ask for Objective ──
    section_divider("Objective", console=console)
    objective = ask_objective(console)
    session.objective = objective

    # ── Step 11: Generate Plan ──
    session.set_state(ExecutionState.PLANNING)
    section_divider("Planning", console=console)
    console.print("[dim]Generating assessment plan...[/dim]\n")

    planner = Planner(session, console, hint_engine=hint_engine)
    plan_phases = planner.generate_plan()

    # Create phases in session
    for p in plan_phases:
        session.add_phase(
            name=p["name"],
            description=p.get("description", ""),
            tools=p.get("tools", []),
        )

    # Display the plan
    plan_tree(
        [{"name": p.name, "description": p.description, "tools": p.tools, "status": p.status}
         for p in session.phases],
        console=console,
    )

    # ── Step 12: Confirm Plan ──
    action = confirm_plan(console)
    if action == "abort":
        console.print("[bold red]Session aborted by auditor.[/bold red]")
        session.set_state(ExecutionState.PAUSED)
        session.save()
        return
    elif action == "modify":
        modification = ask_modification(console)
        hint_engine.add_hint(modification, hint_type=HintType.CONTEXT, priority="high")
        session.auditor_hints.append(modification)
        # Replan
        session.clear_phases()
        plan_phases = planner.generate_plan()
        for p in plan_phases:
            session.add_phase(
                name=p["name"],
                description=p.get("description", ""),
                tools=p.get("tools", []),
            )
        plan_tree(
            [{"name": p.name, "description": p.description, "tools": p.tools, "status": p.status}
             for p in session.phases],
            console=console,
        )
        action = confirm_plan(console)
        if action == "abort":
            console.print("[bold red]Session aborted by auditor.[/bold red]")
            session.set_state(ExecutionState.PAUSED)
            session.save()
            return

    # ── Step 13: Execute Phases ──
    _execute_phases(session, all_tools, policy, planner, hint_engine, console)


# ═══════════════════════════════════════════
#  Resume Session
# ═══════════════════════════════════════════

def _resume_session(session_dir: str) -> None:
    """Resume a previously saved session."""
    show_banner(console)
    console.print(f"[dim]Loading session from {session_dir}...[/dim]\n")

    session = Session.load(session_dir)
    all_tools = load_all_tools()

    # Restore hint engine
    hint_engine = HintEngine()
    if session.hints_data:
        hint_engine.load_from_list(session.hints_data)

    # Show session info
    info_panel(
        "📋 Resumed Session",
        f"ID: {session.session_id}\n"
        f"Type: {session.assessment_type.get('name', '?')}\n"
        f"Objective: {session.objective}\n"
        f"State: {session.execution_state.value}\n"
        f"Phases: {len(session.completed_phases)}/{len(session.phases)} completed\n"
        f"Findings: {len(session.all_findings)}\n"
        f"Errors: {len(session.errors)}",
        console=console,
    )

    # Show findings so far
    if session.all_findings:
        findings_table(
            [f.to_dict() for f in session.all_findings[:10]],
            title=f"Previous Findings ({len(session.all_findings)} total)",
            console=console,
        )

    # Recreate policy engine
    policy = PolicyEngine(
        domains=session.scope["domains"],
        ips=session.scope.get("ips", []),
        urls=session.scope.get("urls", []),
        ports=session.scope.get("ports", ["1-65535"]),
        exclusions=session.scope.get("exclusions", []),
        intensity=session.intensity,
        assessment_type=session.assessment_type.get("key", "web"),
    )

    planner = Planner(session, console, hint_engine=hint_engine)

    # Continue execution from where we left off
    _execute_phases(session, all_tools, policy, planner, hint_engine, console)


# ═══════════════════════════════════════════
#  Phase Execution Engine (shared by start & resume)
# ═══════════════════════════════════════════

def _execute_phases(
    session: Session,
    all_tools: dict,
    policy: PolicyEngine,
    planner: Planner,
    hint_engine: HintEngine,
    con: Console,
) -> None:
    """Execute assessment phases with full error handling and hinting."""

    executor = Executor(session, policy, con)
    analyzer = Analyzer(session, con)
    session.set_state(ExecutionState.EXECUTING)

    con.print()
    section_divider("Execution", console=con)
    con.print()

    for phase_idx, phase in enumerate(session.phases):
        # Skip already-completed or skipped phases
        if phase.status in ("done", "skipped"):
            con.print(f"  [dim]⏭ Phase {phase.number}: {phase.name} — {phase.status}[/dim]")
            continue

        session.current_phase = phase_idx
        phase.status = "running"
        session.log_event("phase_start", f"Phase {phase.number}: {phase.name}")
        session.auto_save()

        phase_header(phase.number, phase.name, console=con)
        con.print(f"  [dim]{phase.description}[/dim]\n")

        # Show active hints for this phase
        hints_ctx = hint_engine.get_hints_for_context(phase.number)
        if hints_ctx:
            info_panel("💡 Active Hints", hints_ctx, console=con)

        # Pre-phase hint opportunity
        pre_hint = ask_pre_phase_hint(phase.name, console=con)
        if pre_hint:
            hint_engine.add_hint(pre_hint, hint_type=HintType.CONTEXT, phase_target=phase.number)
            session.auditor_hints.append(pre_hint)
            con.print(f"  [dim green]v Hint noted[/dim green]")

        # Resolve tool names to tool definitions
        phase_tool_names = hint_engine.apply_to_phase_tools(phase.tools)
        phase_tools = _resolve_phase_tools(phase_tool_names, all_tools, session.assessment_type.get("key", "web"))

        if not phase_tools:
            con.print("  [dim yellow]No matching tools available for this phase.[/dim yellow]")
            if "analysis" in phase.name.lower() or "deep" in phase.name.lower():
                _run_deep_analysis(session, analyzer, con)
            phase.status = "done"
            session.log_event("phase_end", f"Phase {phase.number}: no tools, marked done")
            session.auto_save()
            continue

        # Execute each tool (continue on failure)
        for tool_def in phase_tools:
            for target in session.targets:
                try:
                    result = executor.execute(tool_def, target)
                    from aquiles.core.session import ToolResult as TR
                    from aquiles.core.policy import PolicyViolation
                    if isinstance(result, TR):
                        # Results are tracked on phase by session.add_tool_result()
                        if result.succeeded or result.has_output:
                            findings = analyzer.analyze_result(result)
                            new_count = 0
                            for f in findings:
                                if session.add_finding(f):
                                    # Findings tracked on phase by session
                                    phase.findings.append(f)
                                    new_count += 1
                            if new_count:
                                con.print(f"    [bright_green]→ {new_count} new findings[/bright_green]")
                except Exception as e:
                    error_panel("Tool Error", f"{tool_def.name}: {e}", console=con)
                    session.log_error({
                        "tool": tool_def.name,
                        "target": target,
                        "error": str(e),
                        "phase": phase.number,
                    })
                    # Continue with next tool — partial phase continuation
                    continue

        phase.status = "done"
        session.log_event("phase_end", f"Phase {phase.number}: {phase.name} completed")

        # Phase summary — use ACTUAL phase results and findings
        con.print()
        phase_summary = analyzer.analyze_phase(phase.results, phase.findings)
        _show_phase_summary(phase, phase_summary, con)

        # Phase-end retry prompt if there were failures
        if phase.failed_tools:
            retry_action = ask_retry_failed(phase.failed_tools, console=con)
            if retry_action == "retry":
                con.print("  [yellow]Retrying failed tools...[/yellow]")
                new_results = executor.retry_failed(phase, all_tools)
                for r in new_results:
                    if r.succeeded or r.has_output:
                        findings = analyzer.analyze_result(r)
                        for f in findings:
                            session.add_finding(f)
            elif retry_action == "stop":
                con.print("\n[bold yellow]Assessment stopped by auditor.[/bold yellow]")
                session.set_state(ExecutionState.PAUSED)
                session.save()
                break

        session.auto_save()

        # Ask auditor what to do next
        if phase_idx < len(session.phases) - 1:
            has_failures = bool(phase.failed_tools)
            action = ask_phase_action(phase.name, has_failures=has_failures, console=con)

            if action == "stop":
                con.print("\n[bold yellow]Assessment stopped by auditor.[/bold yellow]")
                session.set_state(ExecutionState.PAUSED)
                session.save()
                break

            elif action == "skip":
                next_phase = session.phases[phase_idx + 1]
                next_phase.status = "skipped"
                con.print(f"  [dim]Skipping: {next_phase.name}[/dim]")
                continue

            elif action == "hint":
                hint_data = ask_hint_details(console=con)
                hint_engine.add_hint(
                    hint_data["text"],
                    hint_type=hint_data["hint_type"],
                    priority=hint_data["priority"],
                )
                session.auditor_hints.append(hint_data["text"])
                session.hints_data = hint_engine.to_list()
                con.print(f"  [green]v[/green] Hint added: [dim]{hint_data['text']}[/dim]")

            elif action == "reprioritize":
                remaining_names = [
                    p.name for p in session.phases[phase_idx + 1:]
                    if p.status == "pending"
                ]
                if remaining_names:
                    reprio = ask_reprioritize(remaining_names, console=con)
                    if reprio["action"] == "reorder":
                        _apply_reorder(session, phase_idx + 1, reprio["indices"])
                        con.print("  [green]v[/green] Phases reordered")
                    elif reprio["action"] == "inject":
                        new_phase_data = planner.inject_phase(reprio["phase_name"])
                        injected = session.add_phase(
                            name=new_phase_data["name"],
                            description=new_phase_data["description"],
                            tools=new_phase_data["tools"],
                        )
                        con.print(f"  [green]v[/green] Injected phase: {injected.name}")
                else:
                    con.print("  [dim]No remaining phases to reprioritize.[/dim]")

            elif action == "retry":
                if phase.failed_tools:
                    con.print("  [yellow]Retrying failed tools...[/yellow]")
                    executor.retry_failed(phase, all_tools)

            # Adaptive replanning
            if session.all_findings:
                remaining = [
                    {"name": p.name, "description": p.description, "tools": p.tools}
                    for p in session.phases[phase_idx + 1:]
                    if p.status == "pending"
                ]
                if remaining:
                    adapted = planner.adapt_plan(remaining, session.get_context_summary())
                    pending_idx = 0
                    for p in session.phases[phase_idx + 1:]:
                        if p.status == "pending" and pending_idx < len(adapted):
                            p.tools = adapted[pending_idx].get("tools", p.tools)
                            pending_idx += 1

    # ── Final Report ──
    con.print()
    section_divider("Assessment Complete", console=con)
    con.print()

    session.set_state(ExecutionState.COMPLETED)
    reporter = Reporter(session, con)

    # Show final findings
    if session.all_findings:
        findings_table(
            [f.to_dict() for f in session.all_findings],
            title="All Findings",
            console=con,
        )

    # Get AI recommendations
    recs = analyzer.get_ai_recommendations()
    con.print()
    info_panel("*  Recommendations", recs, console=con)

    # Generate reports
    con.print()
    report_path = reporter.generate_full_report()
    log_path = reporter.generate_session_log()
    session_path = session.save()

    # Save hints for potential resume
    session.hints_data = hint_engine.to_list()
    session.save()

    con.print()
    success_panel(
        "Session Complete",
        f"📄 Assessment Report: {report_path}\n"
        f"📋 Session Log: {log_path}\n"
        f"💾 Session Data: {session_path}\n"
        f"* Total Findings: {len(session.all_findings)}\n"
        f"🔄 Errors Recovered: {len(session.errors)}\n"
        f"💡 Hints Used: {hint_engine.count}\n"
        f"\n📁 All outputs: {session.workspace}\n"
        f"\n[dim]To resume later: aquiles resume {session.workspace}[/dim]",
        console=con,
    )


# ═══════════════════════════════════════════
#  Helper Functions
# ═══════════════════════════════════════════

def _resolve_phase_tools(tool_names: list[str], all_tools: dict, assessment_type: str) -> list:
    """
    Resolve tool name patterns to actual tool definitions.
    
    Multi-strategy matching:
    1. Exact catalog name (e.g., 'nmap_quick_scan')
    2. Prefix match (e.g., 'nmap' → nmap_quick_scan, nmap_service_scan, ...)
    3. Binary name match (e.g., 'subfinder' → subfinder_enum)
    4. Tag match (e.g., 'dns' → all tools tagged 'dns')
    5. Category/subcategory match (e.g., 'recon' → all recon tools)
    """
    resolved = []
    seen = set()

    for name in tool_names:
        name_lower = name.lower().strip()
        if not name_lower:
            continue

        # 1. Exact match
        if name_lower in all_tools:
            tool = all_tools[name_lower]
            if tool.name not in seen and assessment_type in tool.assessment_types:
                resolved.append(tool)
                seen.add(tool.name)
            continue

        # 2. Prefix match
        prefix_matches = [
            t for t in all_tools.values()
            if t.name.startswith(name_lower) and t.name not in seen
            and assessment_type in t.assessment_types
        ]
        if prefix_matches:
            for t in prefix_matches:
                resolved.append(t)
                seen.add(t.name)
            continue

        # 3. Binary name match (AI might say "subfinder" but catalog entry is "subfinder_enum")
        binary_matches = [
            t for t in all_tools.values()
            if t.binary.lower() == name_lower and t.name not in seen
            and assessment_type in t.assessment_types
        ]
        if binary_matches:
            for t in binary_matches:
                resolved.append(t)
                seen.add(t.name)
            continue

        # 4. Tag match (e.g., "dns", "subdomain", "vuln")
        tag_matches = [
            t for t in all_tools.values()
            if name_lower in t.tags and t.name not in seen
            and assessment_type in t.assessment_types
        ]
        if tag_matches:
            for t in tag_matches:
                resolved.append(t)
                seen.add(t.name)
            continue

        # 5. Category/subcategory match (e.g., "recon", "enumeration", "web")
        cat_matches = [
            t for t in all_tools.values()
            if (t.category.lower() == name_lower or t.subcategory.lower() == name_lower)
            and t.name not in seen
            and assessment_type in t.assessment_types
        ]
        if cat_matches:
            for t in cat_matches:
                resolved.append(t)
                seen.add(t.name)
            continue

        # 6. Fuzzy: name contains the search term
        fuzzy_matches = [
            t for t in all_tools.values()
            if name_lower in t.name.lower() and t.name not in seen
            and assessment_type in t.assessment_types
        ]
        if fuzzy_matches:
            for t in fuzzy_matches:
                resolved.append(t)
                seen.add(t.name)

    return resolved


def _apply_reorder(session: Session, start_idx: int, new_order: list[int]) -> None:
    """Reorder pending phases in the session based on new index order."""
    pending = [p for p in session.phases[start_idx:] if p.status == "pending"]
    reordered = []
    for idx in new_order:
        if 0 <= idx < len(pending):
            reordered.append(pending[idx])
    # Add any not included in the reorder
    for p in pending:
        if p not in reordered:
            reordered.append(p)

    # Replace in the session phases list
    pending_positions = [i for i, p in enumerate(session.phases) if i >= start_idx and p.status == "pending"]
    for pos, phase in zip(pending_positions, reordered):
        session.phases[pos] = phase
        phase.number = pos + 1


def _show_phase_summary(phase, summary: dict, console: Console) -> None:
    """Display a phase summary."""
    parts = [
        f"Tools run: [bold]{summary['tools_run']}[/bold] ",
        f"([green]{summary['tools_successful']} OK[/green]",
    ]
    if summary['tools_failed']:
        parts.append(f", [red]{summary['tools_failed']} failed[/red]")
    skipped = summary.get('tools_skipped', 0)
    if skipped:
        parts.append(f", [dim yellow]{skipped} skipped[/dim yellow]")
    parts.append(")")

    body = "".join(parts) + f"\nFindings: [bold]{summary['findings_count']}[/bold]"

    if summary.get("findings_by_severity"):
        severity_parts = []
        colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = summary["findings_by_severity"].get(sev, 0)
            if count:
                color = colors.get(sev, "white")
                severity_parts.append(f"[{color}]{sev}: {count}[/{color}]")
        if severity_parts:
            body += f"\n  {' | '.join(severity_parts)}"

    if summary.get("ai_analysis"):
        body += f"\n\n[bold]AI Analysis:[/bold]\n{summary['ai_analysis']}"

    info_panel(f"* Phase {phase.number} Summary", body, console=console)
    phase.summary = summary.get("ai_analysis", f"Found {summary['findings_count']} findings")


def _run_deep_analysis(session: Session, analyzer: Analyzer, console: Console) -> None:
    """Run deep AI-powered analysis of all findings."""
    if not session.all_findings:
        console.print("  [dim]No findings to analyze.[/dim]")
        return

    console.print("  [bright_cyan]Running deep analysis on all findings...[/bright_cyan]")
    recs = analyzer.get_ai_recommendations()
    info_panel("? Deep Analysis Results", recs, console=console)


def main():
    """Entry point for the Aquiles CLI."""
    cli()


if __name__ == "__main__":
    main()
