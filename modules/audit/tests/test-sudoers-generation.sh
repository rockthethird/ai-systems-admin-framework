#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

python3 "$MODULE_DIR/deploy/scripts/policy.py" build \
    --artifacts-dir "$TEMP_DIR/artifacts" >/dev/null
readonly OUTPUT="$TEMP_DIR/artifacts/sudoers-ai-auditor"

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

if grep -Eq 'Generated at:|20[0-9]{2}-[0-9]{2}-[0-9]{2}' "$OUTPUT"; then
    echo "generated sudoers contains nondeterministic time metadata" >&2
    exit 1
fi

visudo -c -f "$OUTPUT" >/dev/null
echo "sudoers generation test passed"
