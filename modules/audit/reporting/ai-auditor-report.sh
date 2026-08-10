#!/bin/bash
set -euo pipefail
umask 077

readonly COLLECTOR="/usr/local/libexec/ai-auditor-inventory"
readonly ANALYZER="/usr/local/libexec/ai-auditor-analyze-inventory"
readonly SANITIZER="/usr/local/libexec/ai-auditor-sanitize-findings"

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
