#!/bin/bash
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly FINDINGS="$(mktemp)"
trap 'rm -f "$FINDINGS"' EXIT

if [ "$#" -ne 1 ]; then
    echo "usage: $0 INVENTORY.json" >&2
    exit 2
fi

/usr/bin/python3 "$SCRIPT_DIR/analyze-inventory.py" "$1" --output "$FINDINGS"
/usr/bin/python3 "$SCRIPT_DIR/sanitize-findings.py" "$FINDINGS"
