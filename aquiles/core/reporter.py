"""Report generation for Aquiles assessments."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console

from aquiles.core.session import Session, Finding
from aquiles.ui.panels import success_panel, info_panel


class Reporter:
    """Generates structured assessment reports."""

    def __init__(self, session: Session, console: Console | None = None):
        self.session = session
        self.console = console or Console()

    def generate_full_report(self) -> str:
        """Generate a complete Markdown report."""
        lines = [
            f"# Aquiles Assessment Report",
            f"",
            f"**Session ID:** {self.session.session_id}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Assessment Type:** {self.session.assessment_type.get('name', 'Unknown')}",
            f"**Intensity:** {self.session.intensity}",
            f"**Objective:** {self.session.objective}",
            f"",
            f"---",
            f"",
        ]

        # Scope Summary
        lines.extend([
            f"## Scope",
            f"",
            f"### Authorized Targets",
        ])
        for t in self.session.targets:
            lines.append(f"- {t}")
        lines.append("")
        if self.session.exclusions:
            lines.append("### Exclusions")
            for e in self.session.exclusions:
                lines.append(f"- {e}")
            lines.append("")

        # Executive Summary
        lines.extend([
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ])
        lines.append(self._executive_summary())
        lines.append("")

        # Findings by Severity
        lines.extend([
            f"---",
            f"",
            f"## Findings",
            f"",
        ])

        findings = sorted(
            self.session.all_findings,
            key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity),
        )

        severity_emoji = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "⚪",
        }

        if findings:
            # Summary table
            by_sev: dict[str, int] = {}
            for f in findings:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in by_sev:
                    lines.append(f"| {severity_emoji.get(sev, '')} {sev.upper()} | {by_sev[sev]} |")
            lines.extend(["", ""])

            # Detailed findings
            for i, f in enumerate(findings, 1):
                emoji = severity_emoji.get(f.severity, "")
                lines.extend([
                    f"### {i}. {emoji} [{f.severity.upper()}] {f.category}",
                    f"",
                    f"- **Description:** {f.description}",
                    f"- **Target:** {f.target}",
                    f"- **Tool:** {f.tool}",
                    f"- **Phase:** {f.phase}",
                ])
                if f.evidence:
                    lines.extend([
                        f"- **Evidence:**",
                        f"  ```",
                        f"  {f.evidence[:500]}",
                        f"  ```",
                        f"",
                    ])
                lines.append("")
        else:
            lines.append("*No findings were identified during this assessment.*\n")

        # Phase Summary
        lines.extend([
            f"---",
            f"",
            f"## Phase Execution Summary",
            f"",
        ])

        for phase in self.session.phases:
            status_icon = {"done": "[+]", "skipped": ">>", "running": ">", "pending": "~"}.get(phase.status, "?")
            lines.append(f"### {status_icon} Phase {phase.number}: {phase.name}")
            lines.append(f"")
            lines.append(f"**Status:** {phase.status}")
            if phase.results:
                lines.append(f"**Tools executed:** {len(phase.results)}")
                for r in phase.results:
                    status = "[+]" if r.exit_code == 0 else "[-]" if r.exit_code > 0 else "[!]"
                    lines.append(f"- {status} `{r.tool_name}` — {r.duration:.1f}s")
            if phase.summary:
                lines.append(f"\n**Summary:** {phase.summary}")
            lines.append("")

        # Tools Used
        lines.extend([
            f"---",
            f"",
            f"## Tools Used",
            f"",
            f"| Tool | Command | Duration | Status |",
            f"|------|---------|----------|--------|",
        ])
        for r in self.session.tool_results:
            status = "[+]" if r.exit_code == 0 else "[-]"
            cmd_short = r.command[:60] + "..." if len(r.command) > 60 else r.command
            lines.append(f"| {r.tool_name} | `{cmd_short}` | {r.duration:.1f}s | {status} |")
        lines.append("")

        # Footer
        lines.extend([
            f"---",
            f"",
            f"*Report generated by Aquiles v1.0.0 — AI-Assisted Pentesting Orchestrator*",
            f"*This report requires manual validation by a qualified security professional.*",
        ])

        report_content = "\n".join(lines)

        # Save report
        report_path = self.session.reports_dir / "assessment_report.md"
        with open(report_path, "w") as f:
            f.write(report_content)

        success_panel(
            "Report Generated",
            f"Full report saved to:\n  {report_path}",
            console=self.console,
        )

        return str(report_path)

    def generate_session_log(self) -> str:
        """Generate a timestamped session log."""
        log_lines = [
            f"# Aquiles Session Log — {self.session.session_id}",
            f"Started: {self.session.start_time}",
            f"Assessment: {self.session.assessment_type.get('name', 'Unknown')}",
            f"Targets: {', '.join(self.session.targets)}",
            f"",
            f"## Command History",
            f"",
        ]

        for r in self.session.tool_results:
            log_lines.extend([
                f"### [{r.timestamp}] {r.tool_name}",
                f"```",
                f"$ {r.command}",
                f"Exit Code: {r.exit_code}",
                f"Duration: {r.duration:.1f}s",
                f"Output: {r.output_file or 'inline'}",
                f"```",
                f"",
            ])

        log_content = "\n".join(log_lines)
        log_path = self.session.reports_dir / "session_log.md"
        with open(log_path, "w") as f:
            f.write(log_content)

        return str(log_path)

    def _executive_summary(self) -> str:
        """Generate an executive summary."""
        findings = self.session.all_findings
        total = len(findings)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        critical = by_sev.get("critical", 0)
        high = by_sev.get("high", 0)

        if total == 0:
            return "The assessment did not identify significant findings in the scanned scope. Further manual analysis may be warranted."

        summary_parts = [
            f"The assessment identified **{total} findings** across the defined scope.",
        ]

        if critical > 0:
            summary_parts.append(f"**{critical} critical** findings require immediate attention.")
        if high > 0:
            summary_parts.append(f"**{high} high-severity** findings should be investigated promptly.")

        # Top categories
        categories: dict[str, int] = {}
        for f in findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        top_cats = sorted(categories.items(), key=lambda x: -x[1])[:3]
        if top_cats:
            cat_strs = [f"{cat} ({count})" for cat, count in top_cats]
            summary_parts.append(f"Most common finding categories: {', '.join(cat_strs)}.")

        summary_parts.append("\n*All findings require manual validation by a qualified security professional.*")

        return " ".join(summary_parts)

    def save_session(self) -> str:
        """Save the full session data."""
        return self.session.save()
