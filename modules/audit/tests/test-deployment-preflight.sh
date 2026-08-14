#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly TEMP_DIR="$(mktemp -d)"
readonly REPO_ROOT="$TEMP_DIR/repo"
readonly MODULE_DIR="$REPO_ROOT/modules/audit"
readonly DEPLOY="$MODULE_DIR/deploy/scripts/deploy.sh"
readonly POLICY="$MODULE_DIR/deploy/scripts/policy.py"
readonly DIRTY_MARKER="$MODULE_DIR/.deployment-preflight-dirty-test"
readonly UNRELATED_ARTIFACT="$MODULE_DIR/deploy/artifacts/unrelated-test-link"
readonly SOURCE_APPROVAL="$SOURCE_MODULE_DIR/deploy/.state/policy-approval.json"
trap 'rm -rf "$TEMP_DIR"' EXIT

source_approval_sha256=""
if [ -e "$SOURCE_APPROVAL" ]; then
    source_approval_sha256="$(sha256sum "$SOURCE_APPROVAL" | cut -d' ' -f1)"
fi

approve_bundle() {
    local digest="$1" policy="$2"
    printf 'llllll%s\n' "$digest" | script -qfec \
        "stty rows 24 cols 80; exec env TERM=xterm-256color python3 '$policy' review" \
        /dev/null >/dev/null
}

mkdir -p "$REPO_ROOT/modules"
cp -a "$SOURCE_MODULE_DIR" "$MODULE_DIR"
rm -rf "$MODULE_DIR/deploy/.state"
git -C "$REPO_ROOT" init -q
git -C "$REPO_ROOT" config user.name "AI Auditor Test"
git -C "$REPO_ROOT" config user.email "ai-auditor-test@invalid"
git -C "$REPO_ROOT" add modules/audit
git -C "$REPO_ROOT" commit -qm "test fixture"

"$DEPLOY" --help >/dev/null
if "$DEPLOY" --unknown >/dev/null 2>&1; then
    echo "deployment accepted an unknown option" >&2
    exit 1
fi
if "$DEPLOY" --check >/dev/null 2>&1; then
    echo "deployment preflight succeeded without root" >&2
    exit 1
fi
if "$DEPLOY" --non-interactive >/dev/null 2>&1; then
    echo "noninteractive deployment accepted a missing approval digest" >&2
    exit 1
fi

if ! sudo -n true >/dev/null 2>&1; then
    echo "deployment root-preflight tests skipped: passwordless sudo unavailable"
    exit 0
fi

python3 "$POLICY" build >/dev/null
test "$(stat -c %a "$MODULE_DIR/deploy/artifacts/rootfs/opt/ai-auditor")" = "755"
bash -s -- "$MODULE_DIR/deploy/artifacts" "$MODULE_DIR/deploy/scripts/lib/identities.sh" <<'SH'
set -euo pipefail
readonly ARTIFACTS_DIR="$1"
fail() { echo "$*" >&2; exit 1; }
source "$2"
load_auditor_users
[[ "${AUDITOR_USERS[*]}" == "ai-auditor-cloud ai-auditor-local" ]]
SH
bundle_sha256="$(sha256sum "$MODULE_DIR/deploy/artifacts/artifact-index.json" | cut -d' ' -f1)"
approve_bundle "$bundle_sha256" "$POLICY"

touch "$DIRTY_MARKER"
if sudo -n "$DEPLOY" --check >/dev/null 2>&1; then
    echo "deployment preflight accepted a dirty tree without override" >&2
    exit 1
fi
sudo -n "$DEPLOY" --check --allow-dirty >/dev/null

ln -s /path/not-used-by-deployment "$UNRELATED_ARTIFACT"
sudo -n "$DEPLOY" --check --allow-dirty >/dev/null

if printf '\n' | script -qfec "sudo -n '$DEPLOY'" \
        "$TEMP_DIR/dirty-prompt.log" >/dev/null 2>&1; then
    echo "interactive deployment accepted the default response" >&2
    exit 1
fi
grep -Fq 'Continue with an uncommitted deployment? [y/N]' "$TEMP_DIR/dirty-prompt.log"
if sudo -n "$DEPLOY" --non-interactive \
        --approved-sha256 "$bundle_sha256" >/dev/null 2>&1; then
    echo "noninteractive deployment accepted a dirty tree without override" >&2
    exit 1
fi
if sudo -n "$DEPLOY" --allow-dirty --non-interactive \
        --approved-sha256 "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then
    echo "noninteractive deployment accepted the wrong bundle digest" >&2
    exit 1
fi

readonly UNVERSIONED_MODULE="$TEMP_DIR/unversioned/modules/audit"
mkdir -p "$(dirname "$UNVERSIONED_MODULE")"
cp -a "$SOURCE_MODULE_DIR" "$UNVERSIONED_MODULE"
rm -rf "$UNVERSIONED_MODULE/deploy/.state"
readonly UNVERSIONED_POLICY="$UNVERSIONED_MODULE/deploy/scripts/policy.py"
readonly UNVERSIONED_DEPLOY="$UNVERSIONED_MODULE/deploy/scripts/deploy.sh"
python3 "$UNVERSIONED_POLICY" build >/dev/null
unversioned_digest="$(sha256sum "$UNVERSIONED_MODULE/deploy/artifacts/artifact-index.json" | cut -d' ' -f1)"
approve_bundle "$unversioned_digest" "$UNVERSIONED_POLICY"
if sudo -n "$UNVERSIONED_DEPLOY" --check >/dev/null 2>&1; then
    echo "deployment preflight accepted unversioned source without override" >&2
    exit 1
fi
sudo -n "$UNVERSIONED_DEPLOY" --check --allow-unversioned >/dev/null

if [ -n "$source_approval_sha256" ]; then
    test -f "$SOURCE_APPROVAL"
    test "$(sha256sum "$SOURCE_APPROVAL" | cut -d' ' -f1)" = "$source_approval_sha256"
else
    test ! -e "$SOURCE_APPROVAL"
fi

echo "deployment preflight tests passed"
