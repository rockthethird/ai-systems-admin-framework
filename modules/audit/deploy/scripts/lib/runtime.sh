# Runtime preflight and deployment stage. Sourced by deploy.sh.

readonly LIBEXEC="/usr/local/libexec"
readonly RUNTIME_FILES=(
    "runtime/collect/ai-auditor-inventory.py:ai-auditor-inventory:0700:python"
    "runtime/reporting/analyze-inventory.py:ai-auditor-analyze-inventory:0700:python"
    "runtime/reporting/sanitize-findings.py:ai-auditor-sanitize-findings:0700:python"
    "runtime/reporting/sanitize-findings-internal.py:ai-auditor-sanitize-findings-internal:0700:python"
    "runtime/reporting/audit_policy.py:audit_policy.py:0600:python"
    "runtime/reporting/sanitize_common.py:sanitize_common.py:0600:python"
    "deploy/artifacts/policy-manifest.json:ai-auditor-policy-manifest.json:0600:json"
    "runtime/reporting/ai-auditor-report.sh:ai-auditor-report:0755:shell"
    "runtime/reporting/ai-auditor-report-internal.sh:ai-auditor-report-internal:0755:shell"
)

preflight_runtime() {
    local entry source _destination _mode kind
    [[ -x /usr/bin/python3 ]] || fail "/usr/bin/python3 is required"
    [[ -x /usr/bin/bash ]] || fail "/usr/bin/bash is required"
    for entry in "${RUNTIME_FILES[@]}"; do
        IFS=: read -r source _destination _mode kind <<<"$entry"
        source="$MODULE_DIR/$source"
        [[ -f "$source" && ! -L "$source" ]] || fail "runtime source is missing or invalid: $source"
        case "$kind" in
            python)
                /usr/bin/python3 -c 'import pathlib, sys; source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"); compile(source, sys.argv[1], "exec")' "$source"
                ;;
            shell) /usr/bin/bash -n "$source" ;;
            json) /usr/bin/python3 -m json.tool "$source" >/dev/null ;;
            *) fail "unknown runtime source type: $kind" ;;
        esac
    done
}

deploy_runtime() {
    local stage_dir entry source destination mode _kind
    echo "Deploying root-owned audit runtime"
    install -d -o root -g root -m 0755 "$LIBEXEC"
    stage_dir="$(mktemp -d "$LIBEXEC/.ai-auditor-tools.XXXXXX")"
    trap "rm -rf -- '$stage_dir'" EXIT
    for entry in "${RUNTIME_FILES[@]}"; do
        IFS=: read -r source destination mode _kind <<<"$entry"
        install -o root -g root -m "$mode" "$MODULE_DIR/$source" "$stage_dir/$destination"
    done
    for entry in "${RUNTIME_FILES[@]}"; do
        IFS=: read -r _source destination _mode _kind <<<"$entry"
        mv -f "$stage_dir/$destination" "$LIBEXEC/$destination"
    done
    rmdir "$stage_dir"
    trap - EXIT
}
