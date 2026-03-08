"""Web crawler and spider output parser."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urljoin


def extract_forms(html_content: str, base_url: str = "") -> list[dict]:
    """Extract forms and their inputs from HTML content."""
    forms = []
    form_pattern = re.compile(r"<form[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
    action_pattern = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    input_pattern = re.compile(
        r'<input[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*type\s*=\s*["\']([^"\']*)["\']|'
        r'<input[^>]*type\s*=\s*["\']([^"\']*)["\'][^>]*name\s*=\s*["\']([^"\']*)["\']|'
        r'<input[^>]*name\s*=\s*["\']([^"\']*)["\']',
        re.IGNORECASE,
    )

    for form_match in form_pattern.finditer(html_content):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        action_m = action_pattern.search(form_html)
        method_m = method_pattern.search(form_html)

        action = action_m.group(1) if action_m else ""
        if base_url and action:
            action = urljoin(base_url, action)

        method = (method_m.group(1) if method_m else "GET").upper()

        inputs = []
        for inp_match in input_pattern.finditer(form_body):
            name = inp_match.group(1) or inp_match.group(4) or inp_match.group(5) or ""
            input_type = inp_match.group(2) or inp_match.group(3) or "text"
            if name:
                inputs.append({"name": name, "type": input_type})

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def extract_links(html_content: str, base_url: str = "") -> list[str]:
    """Extract all links from HTML content."""
    link_pattern = re.compile(r'href\s*=\s*["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
    links = set()

    for match in link_pattern.finditer(html_content):
        href = match.group(1).strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        if base_url:
            href = urljoin(base_url, href)
        links.add(href)

    return sorted(links)


def extract_comments(html_content: str) -> list[str]:
    """Extract HTML comments that might contain sensitive info."""
    comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
    comments = []
    for match in comment_pattern.finditer(html_content):
        comment = match.group(1).strip()
        # Filter out empty or very short comments
        if len(comment) > 5:
            comments.append(comment)
    return comments


def extract_javascript_sources(html_content: str, base_url: str = "") -> list[str]:
    """Extract JavaScript source URLs."""
    script_pattern = re.compile(r'<script[^>]*src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    sources = []
    for match in script_pattern.finditer(html_content):
        src = match.group(1).strip()
        if base_url:
            src = urljoin(base_url, src)
        sources.append(src)
    return sources


def extract_api_endpoints(content: str) -> list[str]:
    """Extract potential API endpoints from JavaScript/HTML content."""
    patterns = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v[0-9]+/[^"\']+)["\']',
        r'["\'](\./api/[^"\']+)["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
        r'XMLHttpRequest.*?open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
    ]

    endpoints = set()
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            endpoint = match.group(1).strip()
            if endpoint and not endpoint.startswith(("http://cdn", "https://cdn", "//cdn")):
                endpoints.add(endpoint)

    return sorted(endpoints)
