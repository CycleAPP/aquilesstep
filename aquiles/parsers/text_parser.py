"""Regex-based text output parser for tools like gobuster, dirb, ffuf, etc."""

from __future__ import annotations

import re
from typing import Any


def parse_gobuster_output(content: str) -> list[dict]:
    """Parse gobuster directory/DNS output."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        # Directory mode: /path (Status: 200) [Size: 1234]
        dir_match = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
        if dir_match:
            results.append({
                "path": dir_match.group(1),
                "status": int(dir_match.group(2)),
                "size": int(dir_match.group(3)),
                "type": "directory",
            })
            continue

        # DNS mode: Found: subdomain.example.com
        dns_match = re.match(r"Found:\s+(\S+)", line)
        if dns_match:
            results.append({
                "subdomain": dns_match.group(1),
                "type": "dns",
            })

    return results


def parse_ffuf_output(content: str) -> list[dict]:
    """Parse ffuf text output."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        # [Status: 200, Size: 1234, Words: 56, Lines: 78, Duration: 123ms]
        match = re.match(
            r"(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)",
            line,
        )
        if match:
            results.append({
                "url": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)),
                "words": int(match.group(4)),
                "lines": int(match.group(5)),
            })
    return results


def parse_dirb_output(content: str) -> list[dict]:
    """Parse dirb output."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        # + http://example.com/admin (CODE:200|SIZE:1234)
        match = re.match(r"\+\s+(https?://\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)", line)
        if match:
            results.append({
                "url": match.group(1),
                "status": int(match.group(2)),
                "size": int(match.group(3)),
            })
    return results


def parse_whois_output(content: str) -> dict:
    """Extract key info from whois output."""
    info = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiry_date": r"(?:Registry Expiry|Expiration) Date:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            info[key] = matches if len(matches) > 1 else matches[0]

    return info


def parse_generic_urls(content: str) -> list[str]:
    """Extract URLs from any text output."""
    url_pattern = r"https?://[^\s<>\"')\]]*"
    return list(set(re.findall(url_pattern, content)))


def parse_generic_ips(content: str) -> list[str]:
    """Extract IP addresses from any text output."""
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return list(set(re.findall(ip_pattern, content)))


def parse_generic_domains(content: str) -> list[str]:
    """Extract domain names from any text output."""
    domain_pattern = r"\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}\b"
    domains = set(re.findall(domain_pattern, content))
    # Filter out common false positives
    false_positives = {"www.w3.org", "xmlns.com", "schemas.xmlsoap.org", "www.google.com"}
    return [d for d in domains if d.lower() not in false_positives]


def count_status_codes(content: str) -> dict[int, int]:
    """Count HTTP status codes in tool output."""
    codes: dict[int, int] = {}
    for match in re.finditer(r"(?:status|code)[:\s]*(\d{3})", content, re.IGNORECASE):
        code = int(match.group(1))
        codes[code] = codes.get(code, 0) + 1
    return codes
