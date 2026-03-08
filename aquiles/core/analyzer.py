"""Two-tier result analysis: local pattern matching + AI interpretation."""

from __future__ import annotations

import json
import os
import re
from typing import Any

from rich.console import Console

from aquiles.core.session import Session, Finding, ToolResult
from aquiles.core.errors import ParserFallbackChain, ToolError, ErrorCategory, ErrorSeverity
from aquiles.core.ai_provider import get_ai_config, get_ai_client
from aquiles.ui.panels import info_panel, warning_panel


# Patterns for local analysis (no AI needed)
INTERESTING_PATTERNS = {
    "admin_panels": {
        "patterns": [
            r"/admin", r"/administrator", r"/wp-admin", r"/manager",
            r"/phpmyadmin", r"/cpanel", r"/console", r"/dashboard",
            r"/login", r"/signin", r"/portal", r"/backend",
        ],
        "severity": "medium",
        "category": "Exposed Admin Interface",
    },
    "sensitive_files": {
        "patterns": [
            r"\.env", r"\.git/", r"\.svn/", r"\.htaccess", r"\.htpasswd",
            r"web\.config", r"robots\.txt", r"sitemap\.xml", r"crossdomain\.xml",
            r"\.DS_Store", r"Thumbs\.db", r"backup", r"\.bak$", r"\.old$",
            r"\.sql$", r"\.dump$", r"config\.php", r"wp-config",
        ],
        "severity": "high",
        "category": "Sensitive File Exposed",
    },
    "debug_endpoints": {
        "patterns": [
            r"/debug", r"/trace", r"/status", r"/health", r"/info",
            r"/actuator", r"/metrics", r"/swagger", r"/api-docs",
            r"/graphql", r"/graphiql", r"/_debug",
        ],
        "severity": "medium",
        "category": "Debug/Info Endpoint",
    },
    "default_creds": {
        "patterns": [
            r"admin:admin", r"root:root", r"test:test",
            r"default password", r"default credentials",
        ],
        "severity": "critical",
        "category": "Default Credentials",
    },
    "version_disclosure": {
        "patterns": [
            r"Apache/\d", r"nginx/\d", r"IIS/\d", r"PHP/\d",
            r"(?im)^X-Powered-By:", r"(?im)^Server:\s+(Apache|nginx|IIS|lighttpd|openresty)", r"(?im)^X-AspNet-Version",
        ],
        "severity": "low",
        "category": "Version Disclosure",
    },
    "interesting_headers": {
        "patterns": [
            r"X-Debug", r"X-Frame-Options:\s*$", r"X-Content-Type-Options:\s*$",
            r"Access-Control-Allow-Origin:\s*\*",
            r"Content-Security-Policy:\s*$",
        ],
        "severity": "medium",
        "category": "Security Header Issue",
    },
    "crypto_issues": {
        "patterns": [
            r"SSLv2", r"SSLv3", r"TLSv1\.0", r"TLSv1\.1",
            r"\bRC4\b", r"\bDES\b", r"\bMD5\b", r"\bSHA1\b",
            r"self-signed", r"expired certificate",
        ],
        "severity": "medium",
        "category": "Cryptographic Issue",
    },
}

# Known vulnerable version patterns
VULN_VERSIONS = {
    r"Apache/2\.4\.(49|50)": ("critical", "Apache Path Traversal (CVE-2021-41773/42013)"),
    r"Apache/2\.4\.([1-3]\d|4[0-8])": ("low", "Apache version may have known CVEs"),
    r"nginx/1\.(1[0-8]|[0-9]\.)": ("low", "Older nginx version"),
    r"PHP/[5-7]\.[0-2]": ("medium", "Older PHP version with known vulnerabilities"),
    r"OpenSSH_[67]\.": ("low", "Older OpenSSH version"),
    r"vsftpd 2\.3\.4": ("critical", "vsftpd 2.3.4 backdoor (CVE-2011-2523)"),
    r"ProFTPD 1\.3\.[0-4]": ("medium", "Older ProFTPD with known issues"),
    r"Microsoft-IIS/[6-7]\.": ("medium", "Older IIS version"),
    r"jQuery/[12]\.": ("low", "Older jQuery version"),
    r"WordPress\s+[1-4]\.": ("medium", "Older WordPress version"),
}


class Analyzer:
    """
    Two-tier analysis engine.

    Tier 1 (Local): Pattern matching, version checking, deduplication.
    Tier 2 (AI): Complex interpretation, prioritization, next-step suggestions.
    """

    def __init__(self, session: Session, console: Console | None = None):
        self.session = session
        self.console = console or Console()
        self._ai_config = get_ai_config()
        self._ai_available = self._ai_config.available
        self._seen_findings: set[str] = set()

    def analyze_result(self, result: ToolResult) -> list[Finding]:
        """Analyze a single tool result and extract findings."""
        findings: list[Finding] = []

        # Get the output text
        output = result.stdout
        if result.output_file and os.path.exists(result.output_file):
            try:
                with open(result.output_file, "r", errors="ignore") as f:
                    output = f.read()
            except Exception:
                pass

        if not output:
            return findings

        # Tier 1: Local pattern analysis (always runs)
        findings.extend(self._pattern_analysis(output, result))
        findings.extend(self._version_analysis(output, result))

        # Tier 1: Format-specific parsing with fallback chain
        if result.output_file:
            if result.output_file.endswith(".xml"):
                findings.extend(self._parse_with_fallback(output, result, "xml"))
            elif result.output_file.endswith(".json"):
                findings.extend(self._parse_with_fallback(output, result, "json"))

        # Deduplicate
        unique_findings = []
        for f in findings:
            key = f"{f.category}:{f.description}:{f.target}"
            if key not in self._seen_findings:
                self._seen_findings.add(key)
                unique_findings.append(f)

        return unique_findings

    def _parse_with_fallback(self, output: str, result: ToolResult, fmt: str) -> list[Finding]:
        """Parse output with fallback chain: specific → generic → raw text → skip."""
        chain = ParserFallbackChain()

        if fmt == "xml":
            parsed = chain.try_parse(
                [
                    ("nmap_xml", lambda c: self._parse_nmap_findings(c, result)),
                    ("generic_text_patterns", lambda c: self._pattern_analysis(c, result)),
                ],
                output,
                tool_name=result.tool_name,
            )
        elif fmt == "json":
            parsed = chain.try_parse(
                [
                    ("json_parser", lambda c: self._parse_json_findings(c, result)),
                    ("generic_text_patterns", lambda c: self._pattern_analysis(c, result)),
                ],
                output,
                tool_name=result.tool_name,
            )
        else:
            return []

        # Log any parser failures
        for err in chain.errors:
            self.session.log_error(err.to_dict())
            warning_panel(
                "Parser Fallback",
                f"{err.tool_name}: {err.message}",
                console=self.console,
            )

        return parsed if isinstance(parsed, list) else []

    def _parse_json_findings(self, content: str, result: ToolResult) -> list[Finding]:
        """Extract findings from JSON output (nuclei, httpx, etc)."""
        findings = []
        try:
            from aquiles.parsers.json_parser import parse_json_lines, extract_findings_from_nuclei
            records = parse_json_lines(content)
            if records:
                nuclei_findings = extract_findings_from_nuclei(records)
                for nf in nuclei_findings:
                    findings.append(Finding(
                        severity=nf.get("severity", "info"),
                        category=f"Nuclei: {nf.get('name', 'Unknown')}",
                        description=nf.get("description", nf.get("name", "")),
                        target=nf.get("host", nf.get("matched_at", "unknown")),
                        tool=result.tool_name,
                        evidence=nf.get("matched_at", ""),
                        phase=result.phase,
                    ))
        except Exception:
            raise  # Let fallback chain catch this
        return findings if findings else None  # None triggers next parser in chain

    def analyze_phase(self, phase_results: list[ToolResult], phase_findings: list[Finding] | None = None) -> dict:
        """Analyze all results from a phase and produce a summary.
        
        If phase_findings is provided (from CLI loop), use those directly.
        Otherwise, analyze results to extract findings (standalone usage).
        """
        if phase_findings is not None:
            all_findings = phase_findings
        else:
            all_findings = []
            for result in phase_results:
                findings = self.analyze_result(result)
                all_findings.extend(findings)

        summary = self._local_phase_summary(phase_results, all_findings)

        # AI-enhanced summary if available
        if self._ai_available and (all_findings or phase_results):
            try:
                ai_summary = self._ai_phase_analysis(phase_results, all_findings)
                summary["ai_analysis"] = ai_summary
            except Exception as e:
                summary["ai_analysis"] = f"AI analysis unavailable: {e}"

        return summary

    def get_ai_recommendations(self) -> str:
        """Get AI recommendations for next steps based on all findings so far."""
        if not self._ai_available:
            return self._local_recommendations()

        try:
            return self._ai_recommendations()
        except Exception:
            return self._local_recommendations()

    def _pattern_analysis(self, output: str, result: ToolResult) -> list[Finding]:
        """Run pattern matching against output."""
        findings = []
        for pattern_group, config in INTERESTING_PATTERNS.items():
            for pattern in config["patterns"]:
                matches = re.finditer(pattern, output, re.IGNORECASE)
                for match in matches:
                    # Get context: the line containing the match
                    start = max(0, output.rfind("\n", 0, match.start()) + 1)
                    end = output.find("\n", match.end())
                    if end == -1:
                        end = min(len(output), match.end() + 200)
                    context = output[start:end].strip()

                    findings.append(Finding(
                        severity=config["severity"],
                        category=config["category"],
                        description=f"Found: {match.group(0)}",
                        target=result.command.split()[-1] if result.command else "unknown",
                        tool=result.tool_name,
                        evidence=context[:500],
                        phase=result.phase,
                    ))
        return findings

    def _version_analysis(self, output: str, result: ToolResult) -> list[Finding]:
        """Check for known vulnerable versions."""
        findings = []
        for pattern, (severity, description) in VULN_VERSIONS.items():
            matches = re.finditer(pattern, output, re.IGNORECASE)
            for match in matches:
                findings.append(Finding(
                    severity=severity,
                    category="Vulnerable Version",
                    description=f"{description}: {match.group(0)}",
                    target=result.command.split()[-1] if result.command else "unknown",
                    tool=result.tool_name,
                    evidence=match.group(0),
                    phase=result.phase,
                ))
        return findings

    def _parse_nmap_findings(self, xml_content: str, result: ToolResult) -> list[Finding]:
        """Extract findings from nmap XML output."""
        findings = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)

            for host in root.findall(".//host"):
                addr_elem = host.find("address")
                addr = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

                for port in host.findall(".//port"):
                    portid = port.get("portid", "?")
                    protocol = port.get("protocol", "tcp")
                    state_elem = port.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                    if state == "open":
                        service_elem = port.find("service")
                        svc_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                        svc_product = service_elem.get("product", "") if service_elem is not None else ""
                        svc_version = service_elem.get("version", "") if service_elem is not None else ""

                        svc_desc = f"{svc_name}"
                        if svc_product:
                            svc_desc += f" ({svc_product}"
                            if svc_version:
                                svc_desc += f" {svc_version}"
                            svc_desc += ")"

                        findings.append(Finding(
                            severity="info",
                            category="Open Port",
                            description=f"Port {portid}/{protocol}: {svc_desc}",
                            target=addr,
                            tool=result.tool_name,
                            evidence=f"{addr}:{portid} - {svc_desc}",
                            phase=result.phase,
                        ))

                # Check for script output (nmap scripts)
                for script in host.findall(".//script"):
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    if any(kw in script_id.lower() for kw in ["vuln", "exploit", "brute"]):
                        findings.append(Finding(
                            severity="high",
                            category="NSE Script Finding",
                            description=f"Script '{script_id}' found issues",
                            target=addr,
                            tool=result.tool_name,
                            evidence=script_output[:500],
                            phase=result.phase,
                        ))

        except Exception:
            raise  # Let fallback chain catch this
        return findings if findings else None  # None triggers next parser in chain

    def _local_phase_summary(self, results: list[ToolResult], findings: list[Finding]) -> dict:
        """Generate a local summary without AI."""
        successful = [r for r in results if r.exit_code == 0 or (r.error_info and r.error_info.get("severity") == "warning")]
        skipped = [r for r in results if r.exit_code == -1]  # Binary not found
        failed = [r for r in results if r.exit_code > 0 and r not in successful]

        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            "tools_run": len(results) - len(skipped),  # Don't count skipped as "run"
            "tools_successful": len(successful),
            "tools_failed": len(failed),
            "tools_skipped": len(skipped),
            "findings_count": len(findings),
            "findings_by_severity": by_severity,
            "key_findings": [
                {"severity": f.severity, "category": f.category, "description": f.description}
                for f in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity))[:5]
            ],
        }

    def _ai_phase_analysis(self, results: list[ToolResult], findings: list[Finding]) -> str:
        """Use AI to analyze phase results."""
        client = get_ai_client(self._ai_config)
        if not client:
            return "AI analysis unavailable (no API key configured)"

        # Build a summary (NOT raw data) to send to AI
        findings_summary = "\n".join(
            f"- [{f.severity.upper()}] {f.category}: {f.description} (target: {f.target})"
            for f in findings[:20]
        )

        tools_summary = "\n".join(
            f"- {r.tool_name}: exit={r.exit_code}, duration={r.duration:.1f}s"
            for r in results
        )

        prompt = f"""Analyze these pentesting phase results and provide a brief, actionable summary.

Tools executed:
{tools_summary}

Findings:
{findings_summary if findings_summary else "No significant findings in this phase."}

Provide:
1. A 2-3 sentence summary of what was discovered
2. The most interesting finding and why
3. What the auditor should focus on next
4. Any patterns or connections between findings

Be concise and practical. Focus on actionable intelligence."""

        response = client.chat.completions.create(
            model=self._ai_config.model,
            messages=[
                {"role": "system", "content": "You are a penetration testing analyst. Provide concise, actionable analysis."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=500,
        )

        return response.choices[0].message.content.strip()

    def _ai_recommendations(self) -> str:
        """Get AI-powered recommendations."""
        client = get_ai_client(self._ai_config)
        if not client:
            return self._local_recommendations()

        context = self.session.get_context_summary()

        prompt = f"""Based on the following penetration test progress, what should the auditor investigate next?

{context}

Provide 3-5 specific, actionable recommendations ordered by priority.
Consider the assessment type and intensity restrictions.
Be concise."""

        response = client.chat.completions.create(
            model=self._ai_config.model,
            messages=[
                {"role": "system", "content": "You are a penetration testing advisor."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=400,
        )

        return response.choices[0].message.content.strip()

    def _local_recommendations(self) -> str:
        """Generate basic recommendations without AI."""
        findings = self.session.all_findings
        if not findings:
            return "No findings yet. Continue with the planned phases."

        recs = []
        categories = set(f.category for f in findings)

        if "Exposed Admin Interface" in categories:
            recs.append("• Admin interfaces found — test for default credentials and authentication bypass")
        if "Sensitive File Exposed" in categories:
            recs.append("• Sensitive files exposed — check for information disclosure and configuration data")
        if "Debug/Info Endpoint" in categories:
            recs.append("• Debug endpoints found — test for information leakage and unauthenticated access")
        if "Vulnerable Version" in categories:
            recs.append("• Vulnerable versions detected — research specific CVEs and available exploits")
        if "Open Port" in categories:
            recs.append("• Multiple open ports — enumerate services in detail and check for misconfigurations")
        if "Cryptographic Issue" in categories:
            recs.append("• Crypto issues found — downgrade attacks may be possible, check certificate validity")

        if not recs:
            recs.append("• Continue with planned phases and monitor for emerging patterns")

        return "\n".join(recs)
