#!/bin/bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

readonly MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly APP="$MODULE_DIR/deploy/artifacts/rootfs/opt/ai-auditor"
readonly FINDINGS="$(mktemp)"
trap 'rm -f "$FINDINGS"' EXIT

if [ "$#" -ne 1 ]; then
    echo "usage: $0 INVENTORY.json" >&2
    exit 2
fi

[[ -x "$APP/lib/analyze.py" && -x "$APP/lib/sanitize_external.py" ]] || {
    echo "built audit artifacts are missing; review policy and run policy.py build" >&2
    exit 1
}
/usr/bin/python3 "$APP/lib/analyze.py" "$1" --output "$FINDINGS"
/usr/bin/python3 "$APP/lib/sanitize_external.py" "$FINDINGS"
