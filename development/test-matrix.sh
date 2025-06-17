#!/bin/bash
set -e

# Wrapper script for test-matrix.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Ensure Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed"
    exit 1
fi

# Run the Python test script
exec python3 "$SCRIPT_DIR/test-matrix.py" "$@"