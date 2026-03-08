"""Input validation and sanitization utilities."""

from __future__ import annotations

import re
import ipaddress
from urllib.parse import urlparse


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name."""
    if domain.startswith("*."):
        domain = domain[2:]
    pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def is_valid_ip(ip_str: str) -> bool:
    """Validate an IP address or CIDR range."""
    try:
        if "/" in ip_str:
            ipaddress.ip_network(ip_str, strict=False)
        else:
            ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_url(url: str) -> bool:
    """Validate a URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_input(text: str) -> str:
    """Sanitize user input to prevent command injection."""
    # Remove shell metacharacters
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\\"]
    for char in dangerous_chars:
        text = text.replace(char, "")
    return text.strip()


def validate_scope_entry(entry: str) -> tuple[str, bool]:
    """
    Validate a scope entry and return its type and validity.
    Returns (type, is_valid) where type is 'domain', 'ip', 'url', or 'unknown'.
    """
    entry = entry.strip()

    if is_valid_url(entry):
        return "url", True
    if is_valid_ip(entry):
        return "ip", True
    if is_valid_domain(entry):
        return "domain", True

    return "unknown", False
