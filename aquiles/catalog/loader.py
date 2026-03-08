"""YAML-based tool catalog loader."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from aquiles.core.executor import ToolDefinition


CATALOG_DIR = Path(__file__).parent / "tools"


def load_all_tools() -> dict[str, ToolDefinition]:
    """Load all tool definitions from the YAML catalog."""
    tools: dict[str, ToolDefinition] = {}

    for yaml_file in CATALOG_DIR.rglob("*.yaml"):
        try:
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)

            if not data:
                continue

            # Each YAML file can contain a list of tools
            tool_list = data if isinstance(data, list) else [data]

            for tool_data in tool_list:
                if not isinstance(tool_data, dict):
                    continue
                try:
                    tool = ToolDefinition(
                        name=tool_data["name"],
                        display_name=tool_data.get("display_name", tool_data["name"]),
                        binary=tool_data["binary"],
                        category=tool_data.get("category", "general"),
                        subcategory=tool_data.get("subcategory", ""),
                        intensity=tool_data.get("intensity", "medium"),
                        command_template=tool_data["command_template"],
                        output_format=tool_data.get("output_format", "text"),
                        parser=tool_data.get("parser", "text"),
                        description=tool_data.get("description", ""),
                        requires_root=tool_data.get("requires_root", False),
                        timeout=tool_data.get("timeout", 300),
                        assessment_types=tool_data.get("assessment_types", ["web", "infrastructure"]),
                        tags=tool_data.get("tags", []),
                    )
                    tools[tool.name] = tool
                except KeyError:
                    pass  # Skip malformed tool entries

        except Exception:
            pass  # Skip broken YAML files

    return tools


def get_tools_by_category(tools: dict[str, ToolDefinition], category: str) -> list[ToolDefinition]:
    """Filter tools by category."""
    return [t for t in tools.values() if t.category == category]


def get_tools_by_assessment_type(tools: dict[str, ToolDefinition], assessment_type: str) -> list[ToolDefinition]:
    """Filter tools compatible with an assessment type."""
    return [t for t in tools.values() if assessment_type in t.assessment_types]


def get_tools_by_intensity(tools: dict[str, ToolDefinition], max_intensity: str) -> list[ToolDefinition]:
    """Filter tools up to a maximum intensity level."""
    levels = {"low": 0, "medium": 1, "high": 2, "aggressive": 3}
    max_level = levels.get(max_intensity, 1)
    return [t for t in tools.values() if levels.get(t.intensity, 1) <= max_level]


def find_tools_by_prefix(tools: dict[str, ToolDefinition], prefix: str) -> list[ToolDefinition]:
    """Find tools whose name starts with a prefix."""
    return [t for t in tools.values() if t.name.startswith(prefix)]


def find_tools_by_tags(tools: dict[str, ToolDefinition], tags: list[str]) -> list[ToolDefinition]:
    """Find tools that have any of the specified tags."""
    return [t for t in tools.values() if any(tag in t.tags for tag in tags)]


def get_tool_summary(tools: dict[str, ToolDefinition]) -> dict[str, int]:
    """Get a summary count of tools by category."""
    summary: dict[str, int] = {}
    for t in tools.values():
        summary[t.category] = summary.get(t.category, 0) + 1
    return summary
