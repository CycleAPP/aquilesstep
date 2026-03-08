"""Generic JSON output parser for tools like httpx, nuclei, etc."""

from __future__ import annotations

import json
from typing import Any


def parse_json_lines(content: str) -> list[dict]:
    """Parse JSON lines (JSONL) format used by many modern tools."""
    results = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_json_file(content: str) -> Any:
    """Parse a standard JSON file."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return parse_json_lines(content)


def extract_urls_from_httpx(results: list[dict]) -> list[dict]:
    """Extract URL information from httpx JSON output."""
    urls = []
    for r in results:
        url_info = {
            "url": r.get("url", r.get("input", "")),
            "status_code": r.get("status_code", r.get("status-code", 0)),
            "title": r.get("title", ""),
            "tech": r.get("tech", []),
            "content_length": r.get("content_length", r.get("content-length", 0)),
            "webserver": r.get("webserver", ""),
            "host": r.get("host", ""),
        }
        urls.append(url_info)
    return urls


def extract_findings_from_nuclei(results: list[dict]) -> list[dict]:
    """Extract findings from nuclei JSON output."""
    findings = []
    for r in results:
        info = r.get("info", {})
        finding = {
            "template_id": r.get("template-id", r.get("templateID", "")),
            "name": info.get("name", r.get("name", "")),
            "severity": info.get("severity", r.get("severity", "info")),
            "description": info.get("description", ""),
            "matched_at": r.get("matched-at", r.get("matched", "")),
            "host": r.get("host", ""),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
        }
        findings.append(finding)
    return findings
