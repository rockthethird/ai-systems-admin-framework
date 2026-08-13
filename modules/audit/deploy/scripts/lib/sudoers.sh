# Sudoers preflight and deployment stage. Sourced by deploy.sh.

readonly SUDOERS_SOURCE="$ARTIFACTS_DIR/rootfs/etc/sudoers.d/ai-auditor"
readonly SUDOERS_DIR="/etc/sudoers.d"
readonly SUDOERS_TARGET="$SUDOERS_DIR/ai-auditor"

preflight_sudoers() {
    command -v visudo >/dev/null || fail "visudo is required"
    [[ -d "$SUDOERS_DIR" ]] || fail "sudoers directory does not exist: $SUDOERS_DIR"
    [[ -f "$SUDOERS_SOURCE" && ! -L "$SUDOERS_SOURCE" ]] \
        || fail "approved sudoers artifact is missing or invalid"
    visudo -c -f "$SUDOERS_SOURCE" >/dev/null \
        || fail "approved sudoers artifact failed authoritative syntax validation"
}

deploy_sudoers() {
    local candidate
    echo "Deploying approved sudoers policy"
    candidate="$(mktemp "$SUDOERS_DIR/.ai-auditor.XXXXXX")"
    install -o root -g root -m 0440 "$SUDOERS_SOURCE" "$candidate"
    if ! visudo -c -f "$candidate" >/dev/null; then
        rm -f -- "$candidate"
        fail "installed sudoers candidate is invalid"
    fi
    mv -f "$candidate" "$SUDOERS_TARGET"
}
