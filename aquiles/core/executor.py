"""Tool subprocess executor with policy enforcement, retry logic, and error recovery."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from aquiles.core.policy import PolicyEngine, PolicyViolation
from aquiles.core.session import Session, ToolResult
from aquiles.core.errors import (
    ToolError, ErrorSeverity, ErrorCategory,
    classify_error, ParserFallbackChain,
)
from aquiles.core.target import Target, format_target_for_tool, validate_command_target
from aquiles.ui.panels import error_panel, success_panel, info_panel, warning_panel


@dataclass
class ToolDefinition:
    """A tool definition loaded from the catalog."""
    name: str
    display_name: str
    binary: str
    category: str
    subcategory: str
    intensity: str
    command_template: str
    output_format: str
    parser: str
    description: str
    requires_root: bool
    timeout: int
    assessment_types: list[str]
    tags: list[str]


class Executor:
    """
    Executes security tools with policy enforcement and error recovery.

    Features:
    - Canonical target formatting per tool type
    - Preflight validation (command matches authorized scope)
    - Policy validation before every command
    - Configurable retry with exponential backoff
    - Partial output capture on timeout
    - Error classification (recoverable vs fatal)
    """

    def __init__(
        self,
        session: Session,
        policy: PolicyEngine,
        console: Console | None = None,
        max_retries: int = 2,
        retry_backoff: float = 2.0,
    ):
        self.session = session
        self.policy = policy
        self.console = console or Console()
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

        # Build canonical Target objects from session scope
        self._authorized_targets: list[Target] = []
        for t in self.session.targets:
            self._authorized_targets.append(Target.from_raw(t))

    def is_tool_available(self, tool_def: ToolDefinition) -> bool:
        """Check if the tool binary is available and is the correct version."""
        if not shutil.which(tool_def.binary):
            return False

        # Special check: httpx command exists but might be Python httpx (not ProjectDiscovery)
        if tool_def.binary == "httpx" and "-silent" in tool_def.command_template:
            try:
                import subprocess
                r = subprocess.run(["httpx", "--version"], capture_output=True, text=True, timeout=3)
                output = (r.stdout + r.stderr).lower()
                # ProjectDiscovery httpx shows "projectdiscovery" or version like "v1.x.x"
                if "projectdiscovery" not in output and "httpx/" not in output:
                    return False
            except Exception:
                return False

        return True

    def build_command(self, tool_def: ToolDefinition, target: str, extra_args: str = "") -> tuple[str, str]:
        """
        Build command with tool-specific target formatting.
        
        nmap, dig, whois → hostname only
        gobuster dir, nikto, ffuf → URL with scheme
        subfinder, gobuster dns → domain
        """
        output_ext = {"xml": "xml", "json": "json", "csv": "csv"}.get(tool_def.output_format, "txt")
        output_file = self.session.get_output_path(tool_def.name, output_ext)

        # Canonical target formatting
        canonical = Target.from_raw(target)
        target_formats = format_target_for_tool(
            canonical, tool_def.binary, tool_def.command_template
        )

        cmd = tool_def.command_template.format(
            target=target_formats["target"],
            output_file=output_file,
            output_dir=str(self.session.outputs_dir),
            domain=target_formats["domain"],
            ip=target_formats["ip"],
            url=target_formats["url"],
            ports=",".join(str(p) for p in sorted(self.policy.allowed_ports)[:100]) if len(self.policy.allowed_ports) < 100 else "1-65535",
            wordlist="/usr/share/wordlists/dirb/common.txt",
            wordlist_large="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            wordlist_dns="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt" if os.path.exists("/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt") else "/usr/share/wordlists/dirb/common.txt",
        )

        if extra_args:
            cmd = f"{cmd} {extra_args}"

        return cmd, output_file

    def execute(
        self,
        tool_def: ToolDefinition,
        target: str,
        extra_args: str = "",
        dry_run: bool = False,
    ) -> ToolResult | PolicyViolation:
        """
        Execute a tool with full policy validation and retry logic.

        Returns ToolResult on success/failure, PolicyViolation if blocked by policy.
        On recoverable errors, automatically retries up to max_retries times.
        """
        # 1. Validate tool is allowed
        tool_violation = self.policy.validate_tool(tool_def.name)
        if tool_violation:
            error_panel(
                "Policy Violation",
                f"Tool blocked: {tool_violation.detail}",
                console=self.console,
            )
            return tool_violation

        # 2. Validate target is in scope
        target_violation = self.policy.validate_target(target)
        if target_violation:
            error_panel(
                "Policy Violation",
                f"Target blocked: {target_violation.detail}",
                console=self.console,
            )
            return target_violation

        # 3. Build command (with canonical target formatting)
        cmd, output_file = self.build_command(tool_def, target, extra_args)

        # 4. Preflight: verify command only references authorized targets
        if self._authorized_targets:
            is_valid, preflight_err = validate_command_target(cmd, self._authorized_targets)
            if not is_valid:
                error_panel(
                    "Preflight Validation Failed",
                    f"{preflight_err}\n"
                    f"Authorized: {', '.join(t.host for t in self._authorized_targets)}\n"
                    f"Command: {cmd}",
                    console=self.console,
                )
                return PolicyViolation(
                    rule="preflight_target_mismatch",
                    detail=preflight_err,
                )

        # 5. Validate full command (policy engine)
        cmd_violation = self.policy.validate_command(cmd, tool_def.name)
        if cmd_violation:
            error_panel(
                "Policy Violation",
                f"Command blocked: {cmd_violation.detail}",
                console=self.console,
            )
            return cmd_violation

        # 5. Check binary availability
        if not self.is_tool_available(tool_def):
            self.console.print(f"  [dim yellow][!] {tool_def.display_name} not found, skipping...[/dim yellow]")
            result = ToolResult(
                tool_name=tool_def.name,
                command=cmd,
                exit_code=-1,
                output_file="",
                stdout="",
                stderr=f"Binary '{tool_def.binary}' not found on system",
                duration=0,
                phase=self.session.current_phase,
                error_info=classify_error(-1, "not found", tool_def.name).to_dict(),
            )
            self.session.add_tool_result(result)
            return result

        if dry_run:
            info_panel("Dry Run", f"Would execute:\n  {cmd}", console=self.console)
            return ToolResult(
                tool_name=tool_def.name,
                command=cmd,
                exit_code=0,
                output_file=output_file,
                stdout="[dry run]",
                stderr="",
                duration=0,
                phase=self.session.current_phase,
            )

        # 6. Execute with retry logic
        self.session.log_event("tool_start", f"Starting {tool_def.display_name}", metadata={"tool": tool_def.name, "target": target})

        last_result = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                wait_time = self.retry_backoff ** attempt
                self.console.print(
                    f"  [yellow]* Retry {attempt}/{self.max_retries} for {tool_def.display_name} "
                    f"(waiting {wait_time:.0f}s)...[/yellow]"
                )
                time.sleep(wait_time)

            result = self._execute_once(tool_def, cmd, output_file, attempt)
            last_result = result

            if result.succeeded:
                break

            # Classify the error
            tool_error = classify_error(result.exit_code, result.stderr, tool_def.name)
            result.error_info = tool_error.to_dict()
            result.retry_count = attempt

            # Check if the error is just a warning (soft exit code)
            if tool_error.severity == ErrorSeverity.WARNING:
                self.console.print(
                    f"  [dim yellow][!] {tool_def.display_name}: non-zero exit but may have valid output[/dim yellow]"
                )
                # Treat as success — still has usable output
                break

            # Fatal errors — don't retry
            if tool_error.severity == ErrorSeverity.FATAL:
                self.console.print(
                    f"  [red]x {tool_def.display_name}: {tool_error.message} (fatal, skipping)[/red]"
                )
                self.session.log_error(tool_error.to_dict())
                break

            # Recoverable — retry if attempts remain
            if not tool_error.should_retry or attempt >= self.max_retries:
                self.console.print(
                    f"  [red]x {tool_def.display_name}: {tool_error.message} "
                    f"(exhausted {self.max_retries} retries)[/red]"
                )
                self.session.log_error(tool_error.to_dict())
                break

        self.session.add_tool_result(last_result)
        return last_result

    def _execute_once(
        self,
        tool_def: ToolDefinition,
        cmd: str,
        output_file: str,
        attempt: int,
    ) -> ToolResult:
        """Execute a tool command once, capturing output."""
        prefix = f"  [bright_cyan]>[/bright_cyan]" if attempt == 0 else f"  [yellow]*[/yellow]"
        self.console.print(f"{prefix} {tool_def.display_name}: [dim]{cmd}[/dim]")

        start_time = time.time()
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=tool_def.timeout,
                cwd=str(self.session.outputs_dir),
            )
            duration = time.time() - start_time

            result = ToolResult(
                tool_name=tool_def.name,
                command=cmd,
                exit_code=proc.returncode,
                output_file=output_file if os.path.exists(output_file) else "",
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration=duration,
                phase=self.session.current_phase,
            )

            # Save stdout to file if no dedicated output file was created
            if not os.path.exists(output_file) and proc.stdout:
                txt_file = self.session.get_output_path(tool_def.name, "txt")
                with open(txt_file, "w") as f:
                    f.write(proc.stdout)
                result.output_file = txt_file

            if proc.returncode == 0:
                self.console.print(
                    f"  [green][+][/green] {tool_def.display_name} completed "
                    f"[dim]({duration:.1f}s)[/dim]"
                )
                # Show key output lines for verbosity
                self._show_key_output(proc.stdout, tool_def)
            else:
                self.console.print(
                    f"  [yellow][!][/yellow] {tool_def.display_name} exited with code {proc.returncode} "
                    f"[dim]({duration:.1f}s)[/dim]"
                )

            return result

        except subprocess.TimeoutExpired as e:
            duration = time.time() - start_time

            # Capture partial output on timeout
            partial_stdout = ""
            if e.stdout:
                partial_stdout = e.stdout if isinstance(e.stdout, str) else e.stdout.decode("utf-8", errors="ignore")
            partial_stderr = ""
            if e.stderr:
                partial_stderr = e.stderr if isinstance(e.stderr, str) else e.stderr.decode("utf-8", errors="ignore")

            self.console.print(
                f"  [yellow][time] {tool_def.display_name} timed out after {tool_def.timeout}s[/yellow]"
            )

            # Save partial output if we got any
            partial_file = ""
            if partial_stdout:
                partial_file = self.session.get_output_path(f"{tool_def.name}_partial", "txt")
                with open(partial_file, "w") as f:
                    f.write(partial_stdout)
                self.console.print(f"    [dim]Partial output saved ({len(partial_stdout)} chars)[/dim]")

            return ToolResult(
                tool_name=tool_def.name,
                command=cmd,
                exit_code=-2,
                output_file=partial_file or (output_file if os.path.exists(output_file) else ""),
                stdout=partial_stdout,
                stderr=partial_stderr or f"Timed out after {tool_def.timeout}s",
                duration=duration,
                phase=self.session.current_phase,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_panel("Execution Error", f"{tool_def.display_name}: {e}", console=self.console)
            return ToolResult(
                tool_name=tool_def.name,
                command=cmd,
                exit_code=-3,
                output_file="",
                stdout="",
                stderr=str(e),
                duration=duration,
                phase=self.session.current_phase,
            )

    def retry_failed(self, phase: "Phase", all_tools: dict) -> list[ToolResult]:
        """
        Retry all failed tools from a phase.
        Returns list of new results.
        """
        new_results = []
        for tool_name in list(phase.failed_tools):
            if tool_name in all_tools:
                tool_def = all_tools[tool_name]
                for target in self.session.targets:
                    result = self.execute(tool_def, target)
                    if isinstance(result, ToolResult):
                        new_results.append(result)
                        if result.succeeded:
                            phase.failed_tools.remove(tool_name)
        return new_results

    def _show_key_output(self, stdout: str, tool_def: ToolDefinition) -> None:
        """Show key output lines from a tool for verbose feedback."""
        if not stdout or not stdout.strip():
            return

        lines = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
        if not lines:
            return

        # Filter for interesting lines based on tool type
        interesting = []
        for line in lines:
            line_lower = line.lower()
            # Skip noise/boilerplate
            if any(skip in line_lower for skip in [
                "starting", "nmap done", "completed", "warning:",
                "# nmap", "service detection", "note:", "rtt",
                "not shown", "scanned", "hosts up", "raw packets",
            ]):
                continue
            # Keep interesting content
            if any(kw in line_lower for kw in [
                "/tcp", "/udp", "open", "filtered",  # Ports
                "server:", "http/", "nginx", "apache", "ssh",  # Services
                "record", "ns ", "mx ", "a ", "cname", "txt",  # DNS
                "registrar", "creation", "expir", "name server",  # WHOIS
                "vulnerable", "vuln", "cve", "exploit",  # Vulns
                "disallow", "allow", "sitemap",  # robots.txt
                "x-frame", "x-content", "strict-transport", "content-security",  # Headers
                "200", "301", "302", "403", "404", "500",  # Status codes
                "certificate", "ssl", "tls", "cipher",  # SSL
                "found:", "detected", "version",  # Detection
            ]):
                interesting.append(line)

        # If no interesting lines, show first few non-empty lines
        if not interesting:
            interesting = lines[:5]

        # Show max 8 lines
        for line in interesting[:8]:
            # Truncate long lines
            display = line[:120] + "..." if len(line) > 120 else line
            self.console.print(f"    [dim]{display}[/dim]")
