#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly OUTPUT="$(mktemp)"
trap 'rm -f "$OUTPUT"' EXIT

bash "$MODULE_DIR/build/10-generate-sudoers-from-yaml.sh" --output "$OUTPUT" >/dev/null

expected='ai-auditor ALL=(root:root) NOPASSWD: /usr/local/libexec/ai-auditor-report ""'
if ! grep -Fq "$expected" "$OUTPUT"; then
    echo "generated sudoers does not enforce a root-only, no-argument sanitized report" >&2
    exit 1
fi

if grep -Fq '/usr/local/libexec/ai-auditor-inventory' "$OUTPUT"; then
    echo "generated sudoers unexpectedly exposes the raw inventory collector" >&2
    exit 1
fi

if command -v visudo >/dev/null 2>&1; then
    visudo -c -f "$OUTPUT" >/dev/null
fi

echo "sudoers generation test passed"
