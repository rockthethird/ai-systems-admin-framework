#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly LIBEXEC="/usr/local/libexec"
readonly COLLECTOR_SOURCE="$MODULE_DIR/collect/ai-auditor-inventory.py"
readonly ANALYZER_SOURCE="$MODULE_DIR/reporting/analyze-inventory.py"
readonly SANITIZER_SOURCE="$MODULE_DIR/reporting/sanitize-findings.py"
readonly REPORT_SOURCE="$MODULE_DIR/reporting/ai-auditor-report.sh"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

if [ ! -x /usr/bin/python3 ]; then
    echo "ERROR: /usr/bin/python3 is required" >&2
    exit 1
fi

for source in "$COLLECTOR_SOURCE" "$ANALYZER_SOURCE" "$SANITIZER_SOURCE"; do
    /usr/bin/python3 -c 'import pathlib, sys; source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"); compile(source, sys.argv[1], "exec")' "$source"
done
/usr/bin/bash -n "$REPORT_SOURCE"

install -d -o root -g root -m 0755 "$LIBEXEC"
stage_dir="$(mktemp -d "$LIBEXEC/.ai-auditor-tools.XXXXXX")"
trap 'rm -rf -- "$stage_dir"' EXIT
install -o root -g root -m 0700 "$COLLECTOR_SOURCE" "$stage_dir/ai-auditor-inventory"
install -o root -g root -m 0700 "$ANALYZER_SOURCE" "$stage_dir/ai-auditor-analyze-inventory"
install -o root -g root -m 0700 "$SANITIZER_SOURCE" "$stage_dir/ai-auditor-sanitize-findings"
install -o root -g root -m 0755 "$REPORT_SOURCE" "$stage_dir/ai-auditor-report"

# Activate private helpers first and the public endpoint last.
mv -f "$stage_dir/ai-auditor-inventory" "$LIBEXEC/ai-auditor-inventory"
mv -f "$stage_dir/ai-auditor-analyze-inventory" "$LIBEXEC/ai-auditor-analyze-inventory"
mv -f "$stage_dir/ai-auditor-sanitize-findings" "$LIBEXEC/ai-auditor-sanitize-findings"
mv -f "$stage_dir/ai-auditor-report" "$LIBEXEC/ai-auditor-report"
rmdir "$stage_dir"
trap - EXIT

echo "Installed root-only audit helpers and sanitized report endpoint"
