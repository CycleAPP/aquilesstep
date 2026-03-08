"""Error classification and handling for Aquiles tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ErrorSeverity(Enum):
    """How bad is this error?"""
    WARNING = "warning"       # Tool ran but signaled issues (nmap host-down = exit 1)
    RECOVERABLE = "recoverable"  # Timeout, temp network issue — worth retrying
    FATAL = "fatal"           # Binary missing, permission denied — no point retrying


class ErrorCategory(Enum):
    TOOL_NOT_FOUND = "tool_not_found"
    TOOL_TIMEOUT = "tool_timeout"
    TOOL_CRASHED = "tool_crashed"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_ERROR = "network_error"
    POLICY_BLOCKED = "policy_blocked"
    PARSER_FAILED = "parser_failed"
    UNKNOWN = "unknown"


@dataclass
class ToolError:
    """Structured error from a tool execution."""
    category: ErrorCategory
    severity: ErrorSeverity
    tool_name: str
    message: str
    exit_code: int = -1
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    retry_count: int = 0
    max_retries: int = 2

    @property
    def is_recoverable(self) -> bool:
        return self.severity == ErrorSeverity.RECOVERABLE

    @property
    def should_retry(self) -> bool:
        return self.is_recoverable and self.retry_count < self.max_retries

    @property
    def suggested_action(self) -> str:
        actions = {
            ErrorCategory.TOOL_NOT_FOUND: "Install the tool or skip it",
            ErrorCategory.TOOL_TIMEOUT: "Retry with longer timeout or reduced scope",
            ErrorCategory.TOOL_CRASHED: "Check command syntax or retry",
            ErrorCategory.PERMISSION_DENIED: "Run with elevated privileges or skip",
            ErrorCategory.NETWORK_ERROR: "Check connectivity and retry",
            ErrorCategory.POLICY_BLOCKED: "Adjust scope or intensity settings",
            ErrorCategory.PARSER_FAILED: "Falling back to generic parser",
            ErrorCategory.UNKNOWN: "Review error output manually",
        }
        return actions.get(self.category, "Review manually")

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "tool_name": self.tool_name,
            "message": self.message,
            "exit_code": self.exit_code,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count,
            "suggested_action": self.suggested_action,
        }


def classify_error(exit_code: int, stderr: str, tool_name: str = "") -> ToolError:
    """Classify an error from exit code and stderr into a structured ToolError."""
    stderr_lower = stderr.lower() if stderr else ""

    # Binary not found
    if exit_code == -1 or "not found" in stderr_lower or "no such file" in stderr_lower:
        return ToolError(
            category=ErrorCategory.TOOL_NOT_FOUND,
            severity=ErrorSeverity.FATAL,
            tool_name=tool_name,
            message=stderr or "Tool binary not found",
            exit_code=exit_code,
        )

    # Timeout
    if exit_code == -2 or "timed out" in stderr_lower or "timeout" in stderr_lower:
        return ToolError(
            category=ErrorCategory.TOOL_TIMEOUT,
            severity=ErrorSeverity.RECOVERABLE,
            tool_name=tool_name,
            message=stderr or "Tool execution timed out",
            exit_code=exit_code,
        )

    # Permission denied
    if "permission denied" in stderr_lower or "operation not permitted" in stderr_lower:
        return ToolError(
            category=ErrorCategory.PERMISSION_DENIED,
            severity=ErrorSeverity.FATAL,
            tool_name=tool_name,
            message=stderr or "Permission denied",
            exit_code=exit_code,
        )

    # Network errors
    if any(kw in stderr_lower for kw in [
        "connection refused", "network unreachable", "host unreachable",
        "name resolution", "could not resolve", "no route",
    ]):
        return ToolError(
            category=ErrorCategory.NETWORK_ERROR,
            severity=ErrorSeverity.RECOVERABLE,
            tool_name=tool_name,
            message=stderr or "Network error",
            exit_code=exit_code,
        )

    # Known tool-specific "soft" exit codes (not real failures)
    soft_exit_tools = {
        "nmap": {1},        # nmap exit 1 = host seems down
        "nikto": {1},       # nikto exit 1 = found issues (that's good!)
        "gobuster": {1},    # gobuster can exit 1 on finished scans
        "ffuf": {1},
        "whois": {1, 2},    # whois exit 1/2 = TLD not found in registry
        "dnsrecon": {1, 2}, # dnsrecon exit 1 = partial results
        "dnsenum": {1},     # dnsenum exit 1 = partial
        "fierce": {1},      # fierce exit 1 = no results
        "sslscan": {1},     # sslscan exit 1 = connection refused (useful info)
        "enum4linux": {1},  # enum4linux exit 1 = partial
        "nbtscan": {1},
        "dirb": {1},
    }
    tool_base = tool_name.split("_")[0] if tool_name else ""
    if tool_base in soft_exit_tools and exit_code in soft_exit_tools[tool_base]:
        return ToolError(
            category=ErrorCategory.TOOL_CRASHED,
            severity=ErrorSeverity.WARNING,
            tool_name=tool_name,
            message=f"Non-zero exit ({exit_code}) — may still have valid output",
            exit_code=exit_code,
        )

    # Generic crash
    if exit_code > 0:
        return ToolError(
            category=ErrorCategory.TOOL_CRASHED,
            severity=ErrorSeverity.RECOVERABLE,
            tool_name=tool_name,
            message=stderr or f"Tool exited with code {exit_code}",
            exit_code=exit_code,
        )

    # Fallback
    return ToolError(
        category=ErrorCategory.UNKNOWN,
        severity=ErrorSeverity.RECOVERABLE,
        tool_name=tool_name,
        message=stderr or "Unknown error",
        exit_code=exit_code,
    )


class ParserFallbackChain:
    """
    Try multiple parsers in order, falling back on failure.
    
    Chain: specific_parser → generic_parser → raw_text → skip_with_warning
    """

    def __init__(self):
        self.errors: list[ToolError] = []

    def try_parse(self, parsers: list[tuple[str, callable]], content: str, tool_name: str = "") -> Any:
        """
        Try each parser in order. Return first successful result.
        
        parsers: list of (parser_name, parser_function) tuples
        """
        for parser_name, parser_fn in parsers:
            try:
                result = parser_fn(content)
                if result is not None:
                    return result
            except Exception as e:
                self.errors.append(ToolError(
                    category=ErrorCategory.PARSER_FAILED,
                    severity=ErrorSeverity.WARNING,
                    tool_name=tool_name,
                    message=f"Parser '{parser_name}' failed: {e}",
                ))
                continue

        # All parsers failed
        self.errors.append(ToolError(
            category=ErrorCategory.PARSER_FAILED,
            severity=ErrorSeverity.WARNING,
            tool_name=tool_name,
            message="All parsers failed, returning raw content",
        ))
        return None
