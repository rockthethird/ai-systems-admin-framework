#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly COMPILER="$MODULE_DIR/deploy/scripts/policy.py"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

readonly POLICY="$TEMP_DIR/policy"
readonly ARTIFACTS="$TEMP_DIR/artifacts"
readonly STATE="$TEMP_DIR/state"
cp -a "$MODULE_DIR/deploy/policy" "$POLICY"

if python3 "$COMPILER" review --policy-dir "$POLICY" \
        --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null 2>&1; then
    echo "review succeeded without an interactive terminal" >&2
    exit 1
fi
if [ -e "$ARTIFACTS/artifact-index.json" ] || [ -e "$STATE/policy-approval.json" ]; then
    echo "noninteractive review wrote build or approval state" >&2
    exit 1
fi

build_output="$(python3 "$COMPILER" build --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE")"
grep -Fq 'human_approval_status: REQUIRED' <<<"$build_output"
bundle_sha256="$(sha256sum "$ARTIFACTS/artifact-index.json" | cut -d' ' -f1)"

printf '%s\n' "$bundle_sha256" | script -qfec \
    "python3 '$COMPILER' review --policy-dir '$POLICY' --artifacts-dir '$ARTIFACTS' --state-dir '$STATE'" \
    "$TEMP_DIR/review.log" >/dev/null

grep -Fq 'ARTIFACT: sudoers' "$TEMP_DIR/review.log"
grep -Fq 'DESTINATION: /etc/sudoers.d/ai-auditor' "$TEMP_DIR/review.log"
grep -Fq 'ai-auditor-cloud ALL=(root:root) NOPASSWD: /opt/ai-auditor/bin/report-external ""' \
    "$TEMP_DIR/review.log"
grep -Fq 'ARTIFACT INDEX (exact approved bytes)' "$TEMP_DIR/review.log"
grep -Fq "BUNDLE SHA256: $bundle_sha256" "$TEMP_DIR/review.log"

test "$(stat -c %a "$STATE")" = "700"
test "$(stat -c %a "$STATE/policy-approval.json")" = "600"
python3 "$COMPILER" verify --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null
build_output="$(python3 "$COMPILER" build --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE")"
grep -Fq 'human_approval_status: MATCHED' <<<"$build_output"

cp "$STATE/policy-approval.json" "$TEMP_DIR/approval"
printf '%s\n' incorrect-digest | script -qfec \
    "python3 '$COMPILER' review --policy-dir '$POLICY' --artifacts-dir '$ARTIFACTS' --state-dir '$STATE'" \
    /dev/null >/dev/null 2>&1 || true
cmp "$TEMP_DIR/approval" "$STATE/policy-approval.json"

readonly SUDOERS="$ARTIFACTS/rootfs/etc/sudoers.d/ai-auditor"
cp "$SUDOERS" "$TEMP_DIR/sudoers"
chmod u+w "$SUDOERS"
printf '\n# tampered\n' >> "$SUDOERS"
if python3 "$COMPILER" verify --policy-dir "$POLICY" \
        --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null 2>&1; then
    echo "verification accepted a modified artifact" >&2
    exit 1
fi
cp "$TEMP_DIR/sudoers" "$SUDOERS"
chmod 0440 "$SUDOERS"

touch "$ARTIFACTS/rootfs/unexpected"
if python3 "$COMPILER" verify --policy-dir "$POLICY" \
        --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null 2>&1; then
    echo "verification accepted an undeclared rootfs entry" >&2
    exit 1
fi
rm "$ARTIFACTS/rootfs/unexpected"

printf '\n' >> "$POLICY/identities.yaml"
build_output="$(python3 "$COMPILER" build --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE")"
grep -Fq 'human_approval_status: STALE' <<<"$build_output"
if python3 "$COMPILER" verify --policy-dir "$POLICY" \
        --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null 2>&1; then
    echo "verification accepted stale approval after policy change" >&2
    exit 1
fi

echo "policy approval tests passed"
