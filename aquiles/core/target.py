"""Canonical target representation and tool-specific formatting.

Ensures single source of truth for targets throughout the pipeline.
Each tool type gets the correct format:
- nmap, dig, whois → hostname only (never http://)
- gobuster dir, nikto, ffuf, curl → URL with scheme
- gobuster dns, subfinder → base domain
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    """
    Canonical target representation.
    
    Stores the raw input and provides format-specific accessors.
    This is the SINGLE SOURCE OF TRUTH for all target operations.
    """
    raw: str
    host: str       # Always a plain hostname (no scheme, no port, no path)
    scheme: str     # http, https, or empty
    port: int | None = None
    path: str = ""

    @classmethod
    def from_raw(cls, raw_input: str) -> Target:
        """
        Parse raw user input into a canonical Target.
        
        Handles:
        - Plain domains: example.com → host=example.com
        - URLs: https://example.com/app → host=example.com, scheme=https, path=/app
        - IPs: 10.0.0.1 → host=10.0.0.1
        - IP:port: 10.0.0.1:8080 → host=10.0.0.1, port=8080
        """
        raw = raw_input.strip()

        # If it has a scheme, parse as URL
        if "://" in raw:
            parsed = urlparse(raw)
            return cls(
                raw=raw,
                host=parsed.hostname or raw,
                scheme=parsed.scheme or "",
                port=parsed.port,
                path=parsed.path or "",
            )

        # Check for host:port pattern (not a URL)
        if ":" in raw and not raw.startswith("["):
            parts = raw.rsplit(":", 1)
            try:
                port = int(parts[1])
                return cls(raw=raw, host=parts[0], scheme="", port=port)
            except ValueError:
                pass

        # Plain hostname or IP
        return cls(raw=raw, host=raw, scheme="", port=None)

    @property
    def hostname(self) -> str:
        """Plain hostname/IP — for tools like nmap, dig, whois."""
        return self.host

    @property
    def url(self) -> str:
        """Full URL with scheme — for tools like nikto, gobuster dir, curl."""
        scheme = self.scheme or "https"
        base = f"{scheme}://{self.host}"
        if self.port and self.port not in (80, 443):
            base += f":{self.port}"
        if self.path:
            base += self.path
        return base

    @property
    def http_url(self) -> str:
        """HTTP URL (forced http) — for specific testing."""
        base = f"http://{self.host}"
        if self.port and self.port != 80:
            base += f":{self.port}"
        return base

    @property
    def domain(self) -> str:
        """Base domain — for tools like subfinder, gobuster dns."""
        # If it's an IP, return as-is
        if self._is_ip():
            return self.host
        # Return the host (could be subdomain.example.com)
        return self.host

    @property
    def base_domain(self) -> str:
        """Extract just the base domain (e.g., example.com from sub.example.com)."""
        if self._is_ip():
            return self.host
        parts = self.host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return self.host

    def _is_ip(self) -> bool:
        """Check if host is an IP address."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.host))

    def matches_scope(self, authorized: str) -> bool:
        """Check if this target matches an authorized scope entry."""
        auth_lower = authorized.lower()
        host_lower = self.host.lower()

        # Exact match
        if host_lower == auth_lower:
            return True

        # Subdomain match (target is sub.authorized)
        if host_lower.endswith(f".{auth_lower}"):
            return True

        # Wildcard match
        if auth_lower.startswith("*."):
            base = auth_lower[2:]
            if host_lower == base or host_lower.endswith(f".{base}"):
                return True

        return False

    def __str__(self) -> str:
        return self.host


# ── Tool-Specific Target Formatters ──

# Tools that MUST receive hostname/IP only (never a URL)
HOST_ONLY_TOOLS = {
    "nmap", "masscan", "dig", "whois", "host", "nslookup",
    "traceroute", "ping", "dnsrecon", "dnsenum", "fierce",
    "enum4linux", "smbclient", "snmpwalk", "onesixtyone",
    "ldapsearch", "nbtscan", "rpcclient", "showmount",
    "sslscan", "sslyze", "kerbrute", "crackmapexec",
    "bloodhound-python", "impacket-GetNPUsers", "impacket-GetUserSPNs",
    "subfinder",
}

# Tools that MUST receive a URL with scheme
URL_TOOLS = {
    "nikto", "gobuster dir", "dirb", "ffuf", "wfuzz",
    "curl", "httpx", "whatweb", "wafw00f", "nuclei",
}

# Tools that need base domain (no subdomain prefix needed)
DOMAIN_TOOLS = {
    "gobuster dns", "subfinder", "dnsenum", "theHarvester",
    "fierce",
}


def format_target_for_tool(target: Target, tool_binary: str, command_template: str = "") -> dict[str, str]:
    """
    Generate the correct target format for each template placeholder.
    
    Returns a dict with keys: target, domain, ip, url
    Each formatted correctly for the specific tool.
    """
    # Determine tool type from binary name
    is_host_only = tool_binary in HOST_ONLY_TOOLS
    
    # Check if command template uses {url} placeholder — those need scheme
    uses_url_placeholder = "{url}" in command_template
    
    # Check if it's a DNS tool using -d flag (needs domain)
    is_dns_lookup = any(kw in command_template for kw in ["-d {", "--domain {", "dns"])

    # For tools that use {target} and are in HOST_ONLY
    if is_host_only:
        target_val = target.hostname  # Never a URL
    elif "gobuster dir" in command_template or "ffuf" in command_template or "dirb" in command_template:
        target_val = target.url  # Needs scheme
    elif "nikto" in command_template or "curl" in command_template:
        target_val = target.url
    elif "nuclei" in command_template:
        target_val = target.url
    elif "whatweb" in command_template or "wafw00f" in command_template:
        target_val = target.url
    elif "httpx" in command_template:
        target_val = target.hostname  # httpx handles scheme itself
    else:
        target_val = target.hostname  # Default: hostname

    return {
        "target": target_val,
        "domain": target.domain,
        "ip": target.hostname,
        "url": target.url,
    }


def validate_command_target(command: str, authorized_targets: list[Target]) -> tuple[bool, str]:
    """
    Preflight validation: check that the generated command
    only references authorized targets.
    
    Returns (is_valid, error_message).
    """
    found_hosts = set()

    # Extract FULL domain names (word-boundary aware)
    # This matches complete dot-separated hostnames like salesos.ciklo.me
    domain_pattern = r'(?<![/\w])([a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})(?![/\w.])'
    for match in re.finditer(domain_pattern, command):
        candidate = match.group(1).lower()
        # Skip file-system paths
        if "/" in command[max(0, match.start()-2):match.start()]:
            continue
        # Skip common non-target strings
        if candidate in _COMMAND_NOISE:
            continue
        # Skip if it's part of a file path
        if any(candidate.endswith(ext) for ext in [".txt", ".xml", ".json", ".csv", ".html", ".log"]):
            continue
        found_hosts.add(candidate)

    # Extract IP addresses
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    for match in re.finditer(ip_pattern, command):
        found_hosts.add(match.group(1))

    # Validate each found host against authorized targets
    for host in found_hosts:
        authorized = False
        for auth_target in authorized_targets:
            if _host_matches_target(host, auth_target):
                authorized = True
                break
        if not authorized:
            return False, f"Command references unauthorized host: '{host}'"

    return True, ""


def _host_matches_target(host: str, auth_target: Target) -> bool:
    """Check if a host found in a command matches an authorized target."""
    host_lower = host.lower()
    auth_lower = auth_target.host.lower()

    # Exact match
    if host_lower == auth_lower:
        return True

    # Subdomain match
    if host_lower.endswith(f".{auth_lower}"):
        return True

    # Base domain match (salesos.ciklo.me authorizes ciklo.me)
    if auth_lower.endswith(f".{host_lower}"):
        return True

    return False


# Common strings in commands that look like domains but aren't
_COMMAND_NOISE = {
    "output_file", "output.txt", "output.xml", "output.json",
    "dirb.common", "common.txt", "medium.txt",
    "seclists.discovery", "wordlists.dirb", "wordlists.dirbuster",
    "tcp.salesos", "udp.salesos",  # SRV record patterns
    "nmap.org", "github.com",
}
