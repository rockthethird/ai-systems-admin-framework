#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly LIBEXEC="/usr/local/libexec"
readonly COLLECTOR_SOURCE="$MODULE_DIR/collect/ai-auditor-inventory.py"
readonly ANALYZER_SOURCE="$MODULE_DIR/reporting/analyze-inventory.py"
readonly SANITIZER_SOURCE="$MODULE_DIR/reporting/sanitize-findings.py"
readonly INTERNAL_SANITIZER_SOURCE="$MODULE_DIR/reporting/sanitize-findings-internal.py"
readonly POLICY_LOADER_SOURCE="$MODULE_DIR/reporting/audit_policy.py"
readonly SANITIZER_COMMON_SOURCE="$MODULE_DIR/reporting/sanitize_common.py"
readonly POLICY_MANIFEST_SOURCE="$MODULE_DIR/generated/policy-manifest.json"
readonly REPORT_SOURCE="$MODULE_DIR/reporting/ai-auditor-report.sh"
readonly INTERNAL_REPORT_SOURCE="$MODULE_DIR/reporting/ai-auditor-report-internal.sh"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

if [ ! -x /usr/bin/python3 ]; then
    echo "ERROR: /usr/bin/python3 is required" >&2
    exit 1
fi

for source in "$COLLECTOR_SOURCE" "$ANALYZER_SOURCE" "$SANITIZER_SOURCE" "$INTERNAL_SANITIZER_SOURCE" "$POLICY_LOADER_SOURCE" "$SANITIZER_COMMON_SOURCE"; do
    /usr/bin/python3 -c 'import pathlib, sys; source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"); compile(source, sys.argv[1], "exec")' "$source"
done
/usr/bin/bash -n "$REPORT_SOURCE"
/usr/bin/bash -n "$INTERNAL_REPORT_SOURCE"

install -d -o root -g root -m 0755 "$LIBEXEC"
stage_dir="$(mktemp -d "$LIBEXEC/.ai-auditor-tools.XXXXXX")"
trap 'rm -rf -- "$stage_dir"' EXIT
install -o root -g root -m 0700 "$COLLECTOR_SOURCE" "$stage_dir/ai-auditor-inventory"
install -o root -g root -m 0700 "$ANALYZER_SOURCE" "$stage_dir/ai-auditor-analyze-inventory"
install -o root -g root -m 0700 "$SANITIZER_SOURCE" "$stage_dir/ai-auditor-sanitize-findings"
install -o root -g root -m 0700 "$INTERNAL_SANITIZER_SOURCE" "$stage_dir/ai-auditor-sanitize-findings-internal"
install -o root -g root -m 0600 "$POLICY_LOADER_SOURCE" "$stage_dir/audit_policy.py"
install -o root -g root -m 0600 "$SANITIZER_COMMON_SOURCE" "$stage_dir/sanitize_common.py"
install -o root -g root -m 0600 "$POLICY_MANIFEST_SOURCE" "$stage_dir/ai-auditor-policy-manifest.json"
install -o root -g root -m 0755 "$REPORT_SOURCE" "$stage_dir/ai-auditor-report"
install -o root -g root -m 0755 "$INTERNAL_REPORT_SOURCE" "$stage_dir/ai-auditor-report-internal"

# Activate private helpers first and the public endpoint last.
mv -f "$stage_dir/ai-auditor-inventory" "$LIBEXEC/ai-auditor-inventory"
mv -f "$stage_dir/ai-auditor-analyze-inventory" "$LIBEXEC/ai-auditor-analyze-inventory"
mv -f "$stage_dir/ai-auditor-sanitize-findings" "$LIBEXEC/ai-auditor-sanitize-findings"
mv -f "$stage_dir/ai-auditor-sanitize-findings-internal" "$LIBEXEC/ai-auditor-sanitize-findings-internal"
mv -f "$stage_dir/audit_policy.py" "$LIBEXEC/audit_policy.py"
mv -f "$stage_dir/sanitize_common.py" "$LIBEXEC/sanitize_common.py"
mv -f "$stage_dir/ai-auditor-policy-manifest.json" "$LIBEXEC/ai-auditor-policy-manifest.json"
mv -f "$stage_dir/ai-auditor-report" "$LIBEXEC/ai-auditor-report"
mv -f "$stage_dir/ai-auditor-report-internal" "$LIBEXEC/ai-auditor-report-internal"
rmdir "$stage_dir"
trap - EXIT

echo "Installed root-only audit helpers and sanitized report endpoint"
