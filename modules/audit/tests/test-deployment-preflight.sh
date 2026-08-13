#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly DEPLOY="$MODULE_DIR/deploy/scripts/deploy.sh"
readonly POLICY="$MODULE_DIR/deploy/scripts/policy.py"
readonly DIRTY_MARKER="$MODULE_DIR/.deployment-preflight-dirty-test"
readonly UNRELATED_ARTIFACT="$MODULE_DIR/deploy/artifacts/unrelated-test-link"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -f "$DIRTY_MARKER" "$UNRELATED_ARTIFACT"; rm -rf "$TEMP_DIR"' EXIT

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
bundle_sha256="$(sha256sum "$MODULE_DIR/deploy/artifacts/artifact-index.json" | cut -d' ' -f1)"
printf '%s\n' "$bundle_sha256" | script -qfec "python3 '$POLICY' review" /dev/null >/dev/null

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

mkdir -p "$TEMP_DIR/modules"
cp -a "$MODULE_DIR" "$TEMP_DIR/modules/audit"
readonly UNVERSIONED_POLICY="$TEMP_DIR/modules/audit/deploy/scripts/policy.py"
readonly UNVERSIONED_DEPLOY="$TEMP_DIR/modules/audit/deploy/scripts/deploy.sh"
python3 "$UNVERSIONED_POLICY" build >/dev/null
unversioned_digest="$(sha256sum "$TEMP_DIR/modules/audit/deploy/artifacts/artifact-index.json" | cut -d' ' -f1)"
printf '%s\n' "$unversioned_digest" | script -qfec \
    "python3 '$UNVERSIONED_POLICY' review" /dev/null >/dev/null
if sudo -n "$UNVERSIONED_DEPLOY" --check >/dev/null 2>&1; then
    echo "deployment preflight accepted unversioned source without override" >&2
    exit 1
fi
sudo -n "$UNVERSIONED_DEPLOY" --check --allow-unversioned >/dev/null

echo "deployment preflight tests passed"
