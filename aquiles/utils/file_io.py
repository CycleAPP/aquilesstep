"""Safe file I/O operations."""

from __future__ import annotations

import os
from pathlib import Path


def safe_read(filepath: str, max_size: int = 50 * 1024 * 1024) -> str:
    """Read a file with size limits."""
    path = Path(filepath)
    if not path.exists():
        return ""
    if path.stat().st_size > max_size:
        raise ValueError(f"File too large: {path.stat().st_size} > {max_size}")
    with open(path, "r", errors="ignore") as f:
        return f.read()


def safe_write(filepath: str, content: str) -> None:
    """Write content to a file, creating parent directories."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def ensure_dir(dirpath: str) -> Path:
    """Ensure a directory exists."""
    path = Path(dirpath)
    path.mkdir(parents=True, exist_ok=True)
    return path
