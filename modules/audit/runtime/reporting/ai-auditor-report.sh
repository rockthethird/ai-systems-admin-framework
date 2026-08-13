#!/bin/bash
set -euo pipefail
umask 077
export PYTHONDONTWRITEBYTECODE=1

readonly APP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly COLLECTOR="$APP_ROOT/lib/collect.py"
readonly ANALYZER="$APP_ROOT/lib/analyze.py"

case "${0##*/}" in
    report-external)
        readonly SANITIZER="$APP_ROOT/lib/sanitize_external.py"
        readonly LOG_TAG="ai-auditor-report"
        readonly LABEL="audit report"
        ;;
    report-internal)
        readonly SANITIZER="$APP_ROOT/lib/sanitize_internal.py"
        readonly LOG_TAG="ai-auditor-report-internal"
        readonly LABEL="internal audit report"
        ;;
    *)
        echo "unknown AI auditor report endpoint" >&2
        exit 2
        ;;
esac

if [ "$#" -ne 0 ]; then
    echo "${0##*/} does not accept arguments" >&2
    exit 2
fi

work_dir="$(/usr/bin/mktemp -d "/tmp/${LOG_TAG}.XXXXXX")"
readonly work_dir
trap '/usr/bin/rm -rf -- "$work_dir"' EXIT
readonly inventory="$work_dir/inventory.json"
readonly findings="$work_dir/findings.json"
readonly errors="$work_dir/errors.log"

run_stage() {
    local stage="$1"
    shift
    if ! "$@" 2> "$errors"; then
        /usr/bin/logger -t "$LOG_TAG" -- "$stage failed"
        echo "$LABEL generation failed during $stage" >&2
        exit 1
    fi
}

run_stage collection "$COLLECTOR" > "$inventory"
run_stage analysis /usr/bin/python3 "$ANALYZER" "$inventory" --output "$findings"
run_stage sanitization /usr/bin/python3 "$SANITIZER" "$findings"
