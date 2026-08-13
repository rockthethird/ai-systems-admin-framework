#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly MODULE_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
readonly REPO_ROOT="$(cd "$MODULE_DIR/../.." && pwd)"
readonly POLICY_TOOL="$SCRIPT_DIR/policy.py"
readonly POLICY_DIR="$DEPLOY_DIR/policy"
readonly ARTIFACTS_DIR="$DEPLOY_DIR/artifacts"
readonly STATE_DIR="$DEPLOY_DIR/.state"

CHECK_ONLY=false
ALLOW_DIRTY=false
ALLOW_UNVERSIONED=false
NON_INTERACTIVE=false
APPROVED_SHA256=""
VERIFIED_BUNDLE_SHA256=""

fail() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Deploy the approved AI auditor bundle.

Usage:
  sudo modules/audit/deploy/scripts/deploy.sh [options]

Options:
  --check                       Run the complete read-only preflight only
  --allow-dirty                 Permit a Git checkout with uncommitted changes
  --allow-unversioned           Permit source without usable Git provenance
  --non-interactive             Bypass only the final interactive confirmation
  --approved-sha256 DIGEST      Required bundle digest for --non-interactive
  -h, --help                    Show this help
EOF
}

parse_args() {
    while (($#)); do
        case "$1" in
            --check) CHECK_ONLY=true; shift ;;
            --allow-dirty) ALLOW_DIRTY=true; shift ;;
            --allow-unversioned) ALLOW_UNVERSIONED=true; shift ;;
            --non-interactive) NON_INTERACTIVE=true; shift ;;
            --approved-sha256)
                (($# >= 2)) || fail "--approved-sha256 requires a digest"
                APPROVED_SHA256="$2"
                shift 2
                ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown option: $1" ;;
        esac
    done
    if [[ "$NON_INTERACTIVE" == true && -z "$APPROVED_SHA256" ]]; then
        fail "--non-interactive requires --approved-sha256"
    fi
    if [[ "$NON_INTERACTIVE" == false && -n "$APPROVED_SHA256" ]]; then
        fail "--approved-sha256 is valid only with --non-interactive"
    fi
}

require_root() {
    [[ $EUID -eq 0 ]] || fail "deployment and --check must run as root"
}

validate_source_tree() {
    local owner_uid path mode
    owner_uid="$(stat -c %u "$DEPLOY_DIR")"
    while IFS= read -r -d '' path; do
        [[ ! -L "$path" ]] || fail "deployment tree contains a symlink: $path"
        [[ "$(stat -c %u "$path")" == "$owner_uid" ]] \
            || fail "deployment tree has inconsistent ownership: $path"
        mode="$(stat -c %a "$path")"
        (( (8#$mode & 8#022) == 0 )) || fail "deployment tree entry is group/other writable: $path"
    done < <(find "$DEPLOY_DIR" \
        -path "$ARTIFACTS_DIR" -prune -print0 -o -print0)

    [[ ! -L "$ARTIFACTS_DIR" && -d "$ARTIFACTS_DIR" ]] \
        || fail "artifacts path must be a directory: $ARTIFACTS_DIR"
    [[ "$(stat -c %u "$ARTIFACTS_DIR")" == "$owner_uid" ]] \
        || fail "artifacts directory has inconsistent ownership"
    [[ "$(stat -c %a "$ARTIFACTS_DIR")" == 755 ]] \
        || fail "artifacts directory must have mode 0755"
    for path in artifact-index.json; do
        path="$ARTIFACTS_DIR/$path"
        [[ -f "$path" && ! -L "$path" ]] \
            || fail "required artifact must be a regular file: $path"
        [[ "$(stat -c %u "$path")" == "$owner_uid" && "$(stat -c %a "$path")" == 644 ]] \
            || fail "required artifact must match policy owner and mode 0644: $path"
    done

    [[ "$(stat -c %a "$SCRIPT_DIR/deploy.sh")" == 755 ]] \
        || fail "deploy.sh must have mode 0755"
    [[ "$(stat -c %a "$POLICY_TOOL")" == 755 ]] \
        || fail "policy.py must have mode 0755"
    for path in "$SCRIPT_DIR"/lib/*.sh; do
        [[ -f "$path" && ! -L "$path" && "$(stat -c %a "$path")" == 644 ]] \
            || fail "deployment libraries must be regular mode-0644 files: $path"
    done
}

validate_git_state() {
    local resolved status commit response
    if ! resolved="$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" rev-parse --show-toplevel 2>/dev/null)" \
            || [[ "$resolved" != "$REPO_ROOT" ]]; then
        [[ "$ALLOW_UNVERSIONED" == true ]] \
            || fail "Git provenance is unavailable; use --allow-unversioned to proceed"
        echo "WARNING: Git provenance and cleanliness are unavailable (--allow-unversioned)."
        return
    fi

    commit="$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" rev-parse HEAD)"
    status="$(git -c safe.directory="$REPO_ROOT" -C "$REPO_ROOT" status --porcelain)"
    echo "Git commit: $commit"
    if [[ -n "$status" ]]; then
        printf '%s\n' "$status" >&2
        if [[ "$ALLOW_DIRTY" == true ]]; then
            echo "WARNING: Git working tree is dirty (--allow-dirty)."
        elif [[ "$CHECK_ONLY" == true || "$NON_INTERACTIVE" == true ]]; then
            fail "Git working tree is dirty; use --allow-dirty to test this patch"
        else
            echo "WARNING: Deployment may include code that has not been committed or reviewed."
            read -r -p "Continue with an uncommitted deployment? [y/N] " response \
                || response=""
            [[ "${response,,}" == y || "${response,,}" == yes ]] \
                || fail "deployment aborted"
            echo "WARNING: Continuing with an interactively accepted dirty tree."
        fi
    else
        echo "Git working tree: clean"
    fi
}

verify_approved_bundle() {
    local output
    output="$(python3 "$POLICY_TOOL" verify \
        --policy-dir "$POLICY_DIR" --artifacts-dir "$ARTIFACTS_DIR" --state-dir "$STATE_DIR")" \
        || fail "policy bundle is not valid and approved"
    printf '%s\n' "$output"
    VERIFIED_BUNDLE_SHA256="$(sed -n 's/^bundle_sha256: //p' <<<"$output")"
    [[ "$VERIFIED_BUNDLE_SHA256" =~ ^[0-9a-f]{64}$ ]] \
        || fail "policy verification did not return a valid bundle digest"
}

preflight() {
    echo "Running complete deployment preflight"
    validate_source_tree
    validate_git_state
    verify_approved_bundle
    preflight_identities
    preflight_runtime
    preflight_sudoers
    echo "Deployment preflight passed"
}

confirm_deployment() {
    local response
    echo "Approved bundle: $VERIFIED_BUNDLE_SHA256"
    if [[ "$NON_INTERACTIVE" == true ]]; then
        [[ "$APPROVED_SHA256" == "$VERIFIED_BUNDLE_SHA256" ]] \
            || fail "--approved-sha256 does not match the verified bundle"
        return
    fi
    read -r -p "Deploy this approved bundle? [y/N] " response || response=""
    [[ "${response,,}" == y || "${response,,}" == yes ]] || fail "deployment aborted"
}

main() {
    parse_args "$@"
    require_root
    # Validate non-executable stage libraries before loading privileged code.
    validate_source_tree
    source "$SCRIPT_DIR/lib/identities.sh"
    source "$SCRIPT_DIR/lib/runtime.sh"
    source "$SCRIPT_DIR/lib/sudoers.sh"
    preflight
    [[ "$CHECK_ONLY" == true ]] && exit 0
    confirm_deployment
    deploy_identities
    verify_approved_bundle
    stage_runtime
    verify_approved_bundle
    trap rollback_runtime EXIT
    activate_runtime
    deploy_sudoers
    finish_runtime
    remove_legacy_runtime
    trap - EXIT
    echo "AI auditor deployment complete"
}

main "$@"
