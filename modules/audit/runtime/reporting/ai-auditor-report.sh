#!/bin/bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

readonly APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly COLLECTOR="$APP_ROOT/lib/collect.py"
readonly ANALYZER="$APP_ROOT/lib/analyze.py"
readonly SANITIZER="$APP_ROOT/lib/sanitize_external.py"

if [ "$#" -ne 0 ]; then
    echo "ai-auditor-report does not accept arguments" >&2
    exit 2
fi

work_dir="$(/usr/bin/mktemp -d /tmp/ai-auditor-report.XXXXXX)"
readonly work_dir
trap '/usr/bin/rm -rf -- "$work_dir"' EXIT
readonly inventory="$work_dir/inventory.json"
readonly findings="$work_dir/findings.json"
readonly errors="$work_dir/errors.log"

if ! "$COLLECTOR" > "$inventory" 2> "$errors"; then
    /usr/bin/logger -t ai-auditor-report -- "inventory collection failed"
    echo "audit report generation failed during collection" >&2
    exit 1
fi

if ! /usr/bin/python3 "$ANALYZER" "$inventory" --output "$findings" 2> "$errors"; then
    /usr/bin/logger -t ai-auditor-report -- "inventory analysis failed"
    echo "audit report generation failed during analysis" >&2
    exit 1
fi

if ! /usr/bin/python3 "$SANITIZER" "$findings" 2> "$errors"; then
    /usr/bin/logger -t ai-auditor-report -- "findings sanitization failed"
    echo "audit report generation failed during sanitization" >&2
    exit 1
fi
