# Application-tree preflight and deployment stage. Sourced by deploy.sh.

readonly APP_ROOT="/opt/ai-auditor"
readonly APP_SOURCE="$ARTIFACTS_DIR/rootfs/opt/ai-auditor"
APP_STAGE=""
APP_BACKUP=""
readonly LEGACY_RUNTIME_FILES=(
    /usr/local/libexec/ai-auditor-inventory
    /usr/local/libexec/ai-auditor-analyze-inventory
    /usr/local/libexec/ai-auditor-sanitize-findings
    /usr/local/libexec/ai-auditor-sanitize-findings-internal
    /usr/local/libexec/ai-auditor-policy-manifest.json
    /usr/local/libexec/ai-auditor-report
    /usr/local/libexec/ai-auditor-report-internal
    /usr/local/libexec/audit_policy.py
    /usr/local/libexec/sanitize_common.py
)

preflight_runtime() {
    [[ -d "$APP_SOURCE" && ! -L "$APP_SOURCE" ]] \
        || fail "approved application tree is missing or invalid"
    [[ -x /usr/bin/python3 ]] || fail "/usr/bin/python3 is required"
    [[ -x /usr/bin/bash ]] || fail "/usr/bin/bash is required"
}

stage_runtime() {
    echo "Staging approved application tree"
    APP_STAGE="$(mktemp -d /opt/.ai-auditor.new.XXXXXX)"
    cp -a "$APP_SOURCE/." "$APP_STAGE/"
    chmod --reference="$APP_SOURCE" "$APP_STAGE"
    chown -R root:root "$APP_STAGE"
}

activate_runtime() {
    echo "Activating approved application tree"
    if [[ -e "$APP_ROOT" ]]; then
        [[ -d "$APP_ROOT" && ! -L "$APP_ROOT" ]] \
            || fail "existing application path is not a real directory: $APP_ROOT"
        APP_BACKUP="$(mktemp -d /opt/.ai-auditor.previous.XXXXXX)"
        rmdir "$APP_BACKUP"
        mv "$APP_ROOT" "$APP_BACKUP"
    fi
    mv "$APP_STAGE" "$APP_ROOT"
    APP_STAGE=""
}

rollback_runtime() {
    [[ -n "$APP_STAGE" ]] && rm -rf -- "$APP_STAGE"
    if [[ -n "$APP_BACKUP" && -d "$APP_BACKUP" ]]; then
        rm -rf -- "$APP_ROOT"
        mv "$APP_BACKUP" "$APP_ROOT"
    fi
}

finish_runtime() {
    [[ -n "$APP_BACKUP" ]] && rm -rf -- "$APP_BACKUP"
    APP_BACKUP=""
}

remove_legacy_runtime() {
    echo "Removing superseded AI auditor runtime files"
    rm -f -- "${LEGACY_RUNTIME_FILES[@]}"
}
