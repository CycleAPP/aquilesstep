"""Policy engine — scope validation, exclusion enforcement, and command safety."""

from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from fnmatch import fnmatch
from urllib.parse import urlparse


@dataclass
class PolicyViolation:
    """Represents a policy violation."""
    rule: str
    detail: str
    blocked_target: str = ""


class PolicyEngine:
    """
    Controls what Aquiles is allowed to do.

    Validates every tool command against the defined scope before execution.
    Enforces exclusions, intensity limits, and assessment-type restrictions.
    """

    def __init__(
        self,
        domains: list[str] | None = None,
        ips: list[str] | None = None,
        urls: list[str] | None = None,
        ports: list[str] | None = None,
        exclusions: list[str] | None = None,
        intensity: str = "medium",
        assessment_type: str = "web",
    ):
        self.allowed_domains = domains or []
        self.allowed_ips = ips or []
        self.allowed_urls = urls or []
        self.allowed_ports = self._parse_port_ranges(ports or ["1-65535"])
        self.exclusions = exclusions or []
        self.intensity = intensity
        self.assessment_type = assessment_type

        # Tools blocked per intensity level
        self._intensity_blocks: dict[str, list[str]] = {
            "low": [
                "masscan", "hydra", "medusa", "sqlmap", "wfuzz",
                "patator", "john", "hashcat", "dirsearch_aggressive",
            ],
            "medium": [
                "hydra", "medusa", "patator", "john", "hashcat",
            ],
            "high": [],
        }

        # Assessment-type tool restrictions
        self._type_blocks: dict[str, list[str]] = {
            "bug_bounty": [
                "hydra", "medusa", "patator", "masscan",
                "john", "hashcat", "sqlmap",
            ],
        }

        # Build resolved IP networks for fast checking
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for ip_str in self.allowed_ips:
            try:
                self._allowed_networks.append(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass  # Not a valid network, will use string matching

    def validate_target(self, target: str) -> PolicyViolation | None:
        """Check if a target is within scope."""
        # Check exclusions first
        for excl in self.exclusions:
            if self._matches_target(target, excl):
                return PolicyViolation(
                    rule="exclusion",
                    detail=f"Target '{target}' matches exclusion pattern '{excl}'",
                    blocked_target=target,
                )

        # Check if target matches any allowed scope
        if self._is_in_scope(target):
            return None

        return PolicyViolation(
            rule="out_of_scope",
            detail=f"Target '{target}' is not in the authorized scope",
            blocked_target=target,
        )

    def validate_tool(self, tool_name: str) -> PolicyViolation | None:
        """Check if a tool is allowed for current intensity/assessment type."""
        # Check intensity blocks
        blocked = self._intensity_blocks.get(self.intensity, [])
        if tool_name in blocked:
            return PolicyViolation(
                rule="intensity_restriction",
                detail=f"Tool '{tool_name}' is blocked at intensity '{self.intensity}'",
            )

        # Check assessment type blocks
        type_blocked = self._type_blocks.get(self.assessment_type, [])
        if tool_name in type_blocked:
            return PolicyViolation(
                rule="assessment_type_restriction",
                detail=f"Tool '{tool_name}' is restricted for '{self.assessment_type}' assessments",
            )

        return None

    def validate_command(self, command: str, tool_name: str = "") -> PolicyViolation | None:
        """
        Validate a full command string before execution.
        Extracts targets and checks each against the scope.
        """
        # Validate the tool itself
        if tool_name:
            tool_violation = self.validate_tool(tool_name)
            if tool_violation:
                return tool_violation

        # Extract potential targets from command and validate only actual-looking targets
        targets = self._extract_targets_from_command(command)
        for target in targets:
            # Only validate values that look like real targets (domain, IP, URL)
            if not self._looks_like_target(target):
                continue
            violation = self.validate_target(target)
            if violation:
                return violation

        # Check for dangerous flags that shouldn't be used
        dangerous_patterns = [
            (r"\b--proxy\b", "proxy_usage", "Use of proxy flags is not allowed"),
            (r"\b-oG\s*/dev/tcp\b", "data_exfil", "Potential data exfiltration detected"),
            (r"\|\s*nc\s+", "data_exfil", "Piping to netcat may exfiltrate data"),
            (r"\|\s*curl\s+", "data_exfil", "Piping to curl may exfiltrate data"),
            (r"\bwget\s+-O\s*-\s*\|", "data_exfil", "Wget pipe may exfiltrate data"),
        ]

        for pattern, rule, detail in dangerous_patterns:
            if re.search(pattern, command):
                return PolicyViolation(rule=rule, detail=detail)

        return None

    def _is_in_scope(self, target: str) -> bool:
        """Check if target matches any authorized scope entry."""
        # Check against allowed domains (with wildcard support)
        for domain in self.allowed_domains:
            if self._matches_target(target, domain):
                return True

        # Check against allowed IPs/networks
        try:
            target_ip = ipaddress.ip_address(target)
            for network in self._allowed_networks:
                if target_ip in network:
                    return True
        except ValueError:
            pass  # Not an IP address

        # Check against IP strings directly
        for ip_str in self.allowed_ips:
            if target == ip_str:
                return True

        # Check against allowed URLs
        for url in self.allowed_urls:
            parsed = urlparse(url)
            if parsed.hostname and self._matches_target(target, parsed.hostname):
                return True
            if target.startswith(url) or url.startswith(target):
                return True

        # If target is a URL, extract hostname and recheck
        parsed = urlparse(target if "://" in target else f"http://{target}")
        if parsed.hostname and parsed.hostname != target:
            return self._is_in_scope(parsed.hostname)

        return False

    def _matches_target(self, target: str, pattern: str) -> bool:
        """Check if a target matches a pattern (supports wildcards)."""
        target_lower = target.lower().strip()
        pattern_lower = pattern.lower().strip()

        # Direct match
        if target_lower == pattern_lower:
            return True

        # Wildcard subdomain match (*.example.com)
        if pattern_lower.startswith("*."):
            base = pattern_lower[2:]
            if target_lower == base or target_lower.endswith(f".{base}"):
                return True

        # URL path match
        if "/" in pattern_lower:
            if fnmatch(target_lower, pattern_lower):
                return True

        # Subdomain match (target is a subdomain of the pattern)
        if target_lower.endswith(f".{pattern_lower}"):
            return True

        return False

    def _extract_targets_from_command(self, command: str) -> list[str]:
        """Extract potential target addresses from a command string."""
        targets = []
        try:
            parts = shlex.split(command)
        except ValueError:
            parts = command.split()

        # Common patterns for target specification in security tools
        # Flags that typically take a target host/IP/URL as their value
        target_flags = [
            "--target", "--host", "-u", "--url",
            "-d", "--domain", "--ip", "-iL",
        ]

        skip_next = False
        for i, part in enumerate(parts):
            if skip_next:
                skip_next = False
                continue

            # Check if this is a flag that takes a target as next arg
            if part in target_flags and i + 1 < len(parts):
                targets.append(parts[i + 1])
                skip_next = True
                continue

            # Check for flag=value format
            for flag in target_flags:
                if part.startswith(f"{flag}="):
                    targets.append(part.split("=", 1)[1])
                    break

        # Also check the last argument (many tools take target as positional)
        if parts and not parts[-1].startswith("-"):
            last = parts[-1]
            # Check if it looks like a host, IP, or URL
            if self._looks_like_target(last):
                targets.append(last)

        return targets

    def _looks_like_target(self, value: str) -> bool:
        """Heuristic: does this value look like a target?"""
        # IP address pattern
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", value):
            return True
        # Domain pattern
        if re.match(r"^[a-zA-Z0-9*][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}$", value):
            return True
        # URL pattern
        if re.match(r"^https?://", value):
            return True
        return False

    def _parse_port_ranges(self, ports: list[str]) -> set[int]:
        """Parse port ranges into a set of integers."""
        result = set()
        for port_spec in ports:
            for part in port_spec.split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        start, end = part.split("-", 1)
                        result.update(range(int(start), int(end) + 1))
                    except ValueError:
                        pass
                else:
                    try:
                        result.add(int(part))
                    except ValueError:
                        pass
        return result

    def get_summary(self) -> str:
        """Get a human-readable summary of the policy."""
        lines = [
            f"Assessment Type: {self.assessment_type}",
            f"Intensity: {self.intensity}",
            f"Allowed Domains: {', '.join(self.allowed_domains) or 'None'}",
            f"Allowed IPs: {', '.join(self.allowed_ips) or 'None'}",
            f"Allowed URLs: {', '.join(self.allowed_urls) or 'None'}",
            f"Exclusions: {', '.join(self.exclusions) or 'None'}",
        ]
        blocked = self._intensity_blocks.get(self.intensity, [])
        if blocked:
            lines.append(f"Blocked tools (intensity): {', '.join(blocked)}")
        type_blocked = self._type_blocks.get(self.assessment_type, [])
        if type_blocked:
            lines.append(f"Blocked tools (type): {', '.join(type_blocked)}")
        return "\n".join(lines)
