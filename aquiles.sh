#!/bin/bash
# Aquiles Launcher Script
# Activates the virtual environment and runs Aquiles

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "❌ Virtual environment not found. Creating..."
    python3 -m venv "$VENV_DIR" --system-site-packages
    source "$VENV_DIR/bin/activate"
    pip install -e "$SCRIPT_DIR"
else
    source "$VENV_DIR/bin/activate"
fi

aquiles "$@"
