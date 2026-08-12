#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly OUTPUT="$(mktemp)"
trap 'rm -f "$OUTPUT"' EXIT

bash "$MODULE_DIR/deploy/scripts/generate-sudoers.sh" --output "$OUTPUT" >/dev/null

external='ai-auditor-cloud ALL=(root:root) NOPASSWD: /usr/local/libexec/ai-auditor-report ""'
internal='ai-auditor-local ALL=(root:root) NOPASSWD: /usr/local/libexec/ai-auditor-report-internal ""'
if ! grep -Fq "$external" "$OUTPUT" || ! grep -Fq "$internal" "$OUTPUT"; then
    echo "generated sudoers does not enforce both identity-bound report profiles" >&2
    exit 1
fi

if grep -Fq '/usr/local/libexec/ai-auditor-inventory' "$OUTPUT"; then
    echo "generated sudoers unexpectedly exposes the raw inventory collector" >&2
    exit 1
fi

if grep -Eq '^ai-auditor (ALL|[^-])' "$OUTPUT"; then
    echo "generated sudoers unexpectedly retains the legacy identity" >&2
    exit 1
fi

if command -v visudo >/dev/null 2>&1; then
    visudo -c -f "$OUTPUT" >/dev/null
fi

echo "sudoers generation test passed"
