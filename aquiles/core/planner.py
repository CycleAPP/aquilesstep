"""AI-assisted phase planner and adaptive flow controller."""

from __future__ import annotations

import json
import os
from typing import Any

from rich.console import Console

from aquiles.core.session import Session
from aquiles.core.hints import HintEngine, HintType
from aquiles.core.ai_provider import get_ai_config, get_ai_client
from aquiles.ui.panels import info_panel, warning_panel


# Default phase templates when AI is not available
DEFAULT_PHASES = {
    "web": [
        {"name": "DNS & Domain Validation", "description": "Resolve and validate target domains", "tools": ["dig_lookup", "whois_query", "dnsrecon_standard"]},
        {"name": "Subdomain Discovery", "description": "Find subdomains of target domains", "tools": ["subfinder_enum", "dnsenum_standard", "gobuster_dns"]},
        {"name": "Port & Service Scanning", "description": "Identify open ports and running services", "tools": ["nmap_quick_scan", "nmap_service_scan"]},
        {"name": "Web Fingerprinting", "description": "Identify web technologies and frameworks", "tools": ["whatweb_scan", "wafw00f_detect", "httpx_probe"]},
        {"name": "Directory & Path Discovery", "description": "Find hidden paths and files", "tools": ["gobuster_dir", "ffuf_dir", "dirb_scan"]},
        {"name": "Vulnerability Scanning", "description": "Scan for known vulnerabilities", "tools": ["nikto_scan", "nuclei_scan"]},
        {"name": "Deep Analysis", "description": "Analyze findings and identify attack vectors", "tools": []},
    ],
    "infrastructure": [
        {"name": "Host Discovery", "description": "Find live hosts in the target network", "tools": ["nmap_ping_sweep", "nmap_arp_discovery"]},
        {"name": "Port & Service Enumeration", "description": "Detailed port and service scanning", "tools": ["nmap_full_scan", "nmap_service_scan"]},
        {"name": "Service Fingerprinting", "description": "Identify service versions and configurations", "tools": ["nmap_version_scan", "nmap_script_scan"]},
        {"name": "SMB/NetBIOS Enumeration", "description": "Enumerate SMB shares and NetBIOS", "tools": ["enum4linux_scan", "smbclient_list", "nmap_smb_scripts"]},
        {"name": "SNMP Enumeration", "description": "Enumerate SNMP services", "tools": ["snmpwalk_scan", "onesixtyone_scan"]},
        {"name": "Vulnerability Analysis", "description": "Check for known vulns on discovered services", "tools": ["nmap_vuln_scripts", "nuclei_network"]},
        {"name": "Deep Analysis", "description": "Analyze findings and prioritize targets", "tools": []},
    ],
    "active_directory": [
        {"name": "Domain Reconnaissance", "description": "Gather AD domain information", "tools": ["nmap_ad_scan", "dig_srv_records"]},
        {"name": "User Enumeration", "description": "Enumerate domain users", "tools": ["kerbrute_enum", "enum4linux_scan"]},
        {"name": "Share Enumeration", "description": "Find accessible network shares", "tools": ["smbclient_list", "crackmapexec_shares"]},
        {"name": "Kerberos Analysis", "description": "Check for Kerberos vulnerabilities", "tools": ["getnpusers_scan", "crackmapexec_kerberos"]},
        {"name": "LDAP Enumeration", "description": "Enumerate LDAP directory", "tools": ["ldapsearch_scan", "nmap_ldap_scripts"]},
        {"name": "Deep Analysis", "description": "Analyze AD attack paths", "tools": []},
    ],
    "api": [
        {"name": "API Discovery", "description": "Discover API endpoints and documentation", "tools": ["httpx_probe", "ffuf_api_paths", "gobuster_dir"]},
        {"name": "Technology Fingerprinting", "description": "Identify API framework and tech stack", "tools": ["whatweb_scan", "wafw00f_detect"]},
        {"name": "Endpoint Fuzzing", "description": "Fuzz API endpoints for parameters and paths", "tools": ["ffuf_api_fuzz", "wfuzz_params"]},
        {"name": "Vulnerability Scanning", "description": "Scan API for common vulnerabilities", "tools": ["nikto_scan", "nuclei_api"]},
        {"name": "Deep Analysis", "description": "Analyze API attack surface", "tools": []},
    ],
    "bug_bounty": [
        {"name": "DNS & Domain Validation", "description": "Validate target scope", "tools": ["dig_lookup", "whois_query"]},
        {"name": "Subdomain Discovery", "description": "Find in-scope subdomains", "tools": ["subfinder_enum", "dnsenum_standard"]},
        {"name": "Web Probing", "description": "Probe discovered hosts", "tools": ["httpx_probe", "whatweb_scan"]},
        {"name": "Path Discovery", "description": "Find interesting paths (low intensity)", "tools": ["gobuster_dir", "ffuf_dir"]},
        {"name": "Light Vulnerability Scan", "description": "Non-aggressive vulnerability checks", "tools": ["nuclei_scan", "nikto_scan"]},
        {"name": "Deep Analysis", "description": "Prioritize findings for manual review", "tools": []},
    ],
    "network_external": [
        {"name": "Host Discovery", "description": "Discover externally reachable hosts", "tools": ["nmap_ping_sweep", "masscan_quick"]},
        {"name": "Port Scanning", "description": "Enumerate open ports on discovered hosts", "tools": ["nmap_quick_scan", "nmap_service_scan"]},
        {"name": "Service Fingerprinting", "description": "Identify service versions", "tools": ["nmap_version_scan", "whatweb_scan"]},
        {"name": "SSL/TLS Analysis", "description": "Check SSL/TLS configurations", "tools": ["sslscan_check", "sslyze_scan"]},
        {"name": "Vulnerability Scanning", "description": "Check for known vulnerabilities", "tools": ["nmap_vuln_scripts", "nuclei_network"]},
        {"name": "Deep Analysis", "description": "Analyze perimeter security posture", "tools": []},
    ],
}


class Planner:
    """
    Generates and adapts assessment plans.

    Uses OpenAI when available for intelligent planning,
    falls back to predefined templates otherwise.
    """

    def __init__(self, session: Session, console: Console | None = None, hint_engine: HintEngine | None = None):
        self.session = session
        self.console = console or Console()
        self.hint_engine = hint_engine
        self._ai_config = get_ai_config()
        self._ai_available = self._ai_config.available

    def generate_plan(self) -> list[dict]:
        """Generate an assessment plan based on session context."""
        if self._ai_available:
            try:
                return self._ai_generate_plan()
            except Exception as e:
                warning_panel(
                    "AI Planning Unavailable",
                    f"Falling back to template plan. Error: {e}",
                    console=self.console,
                )

        return self._template_plan()

    def adapt_plan(self, remaining_phases: list[dict], new_findings_summary: str) -> list[dict]:
        """Adapt the remaining plan based on new findings."""
        if self._ai_available:
            try:
                return self._ai_adapt_plan(remaining_phases, new_findings_summary)
            except Exception:
                pass
        return remaining_phases  # No adaptation without AI

    def _template_plan(self) -> list[dict]:
        """Generate a plan from predefined templates, adjusted by hints."""
        import shutil
        from aquiles.catalog.loader import load_all_tools
        
        assessment_key = self.session.assessment_type.get("key", "web")
        phases = [dict(p) for p in DEFAULT_PHASES.get(assessment_key, DEFAULT_PHASES["web"])]

        all_tools = load_all_tools()
        binary_map = {t.name: t.binary for t in all_tools}

        # Filter out tools that are not installed on the system
        for phase in phases:
            available_tools = []
            for tool_name in phase["tools"]:
                binary = binary_map.get(tool_name)
                if binary and shutil.which(binary):
                    available_tools.append(tool_name)
            phase["tools"] = available_tools

        # Apply hint adjustments if available
        if self.hint_engine and self.hint_engine.count > 0:
            # Reprioritize phases based on focus/skip hints
            phases = self.hint_engine.get_priority_adjustments(phases)

            # Inject tools from hints into all phases
            for phase in phases:
                phase["tools"] = self.hint_engine.apply_to_phase_tools(phase["tools"])

        return phases

    def reprioritize(self, remaining_phases: list[dict], new_order: list[int] | None = None) -> list[dict]:
        """
        Reorder remaining phases based on auditor reprioritization.
        
        If new_order is provided, use it directly.
        Otherwise, apply hint-based reordering.
        """
        if new_order:
            # Apply explicit reorder
            reordered = []
            for idx in new_order:
                if 0 <= idx < len(remaining_phases):
                    reordered.append(remaining_phases[idx])
            # Append any phases not in the new order
            for i, phase in enumerate(remaining_phases):
                if i not in new_order:
                    reordered.append(phase)
            return reordered

        # Hint-based reordering
        if self.hint_engine and self.hint_engine.count > 0:
            return self.hint_engine.get_priority_adjustments(remaining_phases)

        return remaining_phases

    def inject_phase(self, name: str, position: int | None = None) -> dict:
        """Create and inject a new phase from a name or description."""
        new_phase = {
            "name": name,
            "description": f"Auditor-injected phase: {name}",
            "tools": [],
        }

        # Try to infer tools from the name
        name_lower = name.lower()
        tool_mappings = {
            "ssl": ["sslscan_check", "sslyze_scan"],
            "smb": ["enum4linux_scan", "smbclient_list", "nmap_smb_scripts"],
            "dns": ["dig_lookup", "dnsrecon_standard", "dnsenum_standard"],
            "subdomain": ["subfinder_enum", "gobuster_dns"],
            "web": ["whatweb_scan", "nikto_scan", "gobuster_dir"],
            "api": ["ffuf_api_paths", "ffuf_api_fuzz", "nuclei_api"],
            "vuln": ["nmap_vuln_scripts", "nuclei_scan"],
            "ldap": ["ldapsearch_scan", "nmap_ldap_scripts"],
            "kerberos": ["kerbrute_enum", "getnpusers_scan"],
            "osint": ["theharvester_scan", "sherlock_scan"],
        }
        for keyword, tools in tool_mappings.items():
            if keyword in name_lower:
                new_phase["tools"].extend(tools)

        return new_phase

    def _get_catalog_summary(self) -> str:
        """Build a concise catalog summary for the AI planner."""
        import shutil
        from aquiles.catalog.loader import load_all_tools, get_tools_by_assessment_type
        all_tools = load_all_tools()
        assessment_type = self.session.assessment_type.get("key", "web")
        compatible = get_tools_by_assessment_type(all_tools, assessment_type)

        # Group by category
        by_cat: dict[str, list[str]] = {}
        for t in compatible:
            if not shutil.which(t.binary):
                continue
            cat = t.category
            if cat not in by_cat:
                by_cat[cat] = []
            by_cat[cat].append(f"{t.name} ({t.binary}, {t.intensity})")

        lines = []
        for cat in sorted(by_cat):
            lines.append(f"  [{cat}]")
            for tool_info in by_cat[cat]:
                lines.append(f"    - {tool_info}")
        return "\n".join(lines)

    def _ai_generate_plan(self) -> list[dict]:
        """Use AI to generate an optimized plan."""
        client = get_ai_client(self._ai_config)
        if not client:
            return self._template_plan()

        context = self.session.get_context_summary()

        # Include hint context if available
        hint_context = ""
        if self.hint_engine and self.hint_engine.count > 0:
            hint_context = f"\n{self.hint_engine.get_hints_for_context()}\n"

        # Build catalog summary for the AI
        catalog_info = self._get_catalog_summary()

        prompt = f"""You are an expert penetration tester planning an authorized security assessment.

Context:
{context}
{hint_context}
AVAILABLE TOOLS (use ONLY these exact names or their prefixes/binary names in the tools list):
{catalog_info}

Generate an optimal phased assessment plan. Each phase should have:
- name: short descriptive name
- description: what this phase accomplishes
- tools: list of tool names FROM THE CATALOG ABOVE (use exact catalog names like "nmap_quick_scan", "gobuster_dir", etc. or binary names like "nmap", "gobuster" which will match all tools using that binary)

Respond ONLY with a JSON array of phase objects. 5-8 phases is typical.
Consider the assessment type, intensity level, and any auditor hints.

CRITICAL: Only reference tools from the catalog above. Do NOT invent tool names."""

        response = client.chat.completions.create(
            model=self._ai_config.model,
            messages=[
                {"role": "system", "content": "You are a pentesting planning assistant. Respond only with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=1500,
        )

        content = response.choices[0].message.content.strip()
        # Strip markdown code fences if present
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content.rsplit("```", 1)[0]

        phases = json.loads(content)
        if isinstance(phases, list) and len(phases) > 0:
            return phases

        return self._template_plan()

    def _ai_adapt_plan(self, remaining_phases: list[dict], findings_summary: str) -> list[dict]:
        """Use AI to adapt the plan based on new findings."""
        client = get_ai_client(self._ai_config)
        if not client:
            return remaining_phases

        prompt = f"""You are an expert penetration tester adapting an assessment plan based on new findings.

Current findings summary:
{findings_summary}

Remaining planned phases:
{json.dumps(remaining_phases, indent=2)}

Based on the findings, should the remaining phases be modified?
- Should any phase be prioritized or added?
- Should any phase be skipped because findings make it irrelevant?
- Should any phase get additional tools?

Respond ONLY with the updated JSON array of remaining phases.
Keep the same format: name, description, tools list."""

        response = client.chat.completions.create(
            model=self._ai_config.model,
            messages=[
                {"role": "system", "content": "You are a pentesting planning assistant. Respond only with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=1500,
        )

        content = response.choices[0].message.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1]
            if content.endswith("```"):
                content = content.rsplit("```", 1)[0]

        adapted = json.loads(content)
        if isinstance(adapted, list) and len(adapted) > 0:
            return adapted

        return remaining_phases
