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
readonly REVIEW_COMMAND="stty rows 24 cols 80; exec env TERM=xterm-256color \
python3 '$COMPILER' review --policy-dir '$POLICY' --artifacts-dir '$ARTIFACTS' \
--state-dir '$STATE'"
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

readonly SMALL_ARTIFACTS="$TEMP_DIR/small-artifacts"
readonly SMALL_STATE="$TEMP_DIR/small-state"
readonly SMALL_REVIEW_COMMAND="stty rows 23 cols 80; exec env TERM=xterm-256color \
python3 '$COMPILER' review --policy-dir '$POLICY' --artifacts-dir '$SMALL_ARTIFACTS' \
--state-dir '$SMALL_STATE'"
if printf 'q' | script -qfec "$SMALL_REVIEW_COMMAND" \
        "$TEMP_DIR/small-review.log" >/dev/null 2>&1; then
    echo "review succeeded in a terminal below its minimum size" >&2
    exit 1
fi
grep -Fq 'review requires at least 80 columns by 24 lines' \
    "$TEMP_DIR/small-review.log"
if [ -e "$SMALL_ARTIFACTS/artifact-index.json" ] \
        || [ -e "$SMALL_STATE/policy-approval.json" ]; then
    echo "undersized review wrote build or approval state" >&2
    exit 1
fi

build_output="$(python3 "$COMPILER" build --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE")"
grep -Fq 'human_approval_status: REQUIRED' <<<"$build_output"
bundle_sha256="$(sha256sum "$ARTIFACTS/artifact-index.json" | cut -d' ' -f1)"

if printf 'xq' | script -qfec \
        "$REVIEW_COMMAND" \
        "$TEMP_DIR/aborted-review.log" >/dev/null 2>&1; then
    echo "review succeeded after the reviewer aborted" >&2
    exit 1
fi
grep -Fq 'review aborted; no new approval was recorded' "$TEMP_DIR/aborted-review.log"
if [ -e "$STATE/policy-approval.json" ]; then
    echo "aborted review wrote approval state" >&2
    exit 1
fi

if printf '\004' | script -qfec \
        "$REVIEW_COMMAND" \
        "$TEMP_DIR/eof-review.log" >/dev/null 2>&1; then
    echo "review succeeded after Ctrl-D" >&2
    exit 1
fi
grep -Fq 'review aborted; no new approval was recorded' "$TEMP_DIR/eof-review.log"
if [ -e "$STATE/policy-approval.json" ]; then
    echo "EOF-aborted review wrote approval state" >&2
    exit 1
fi

printf 'llllll%s\n' "$bundle_sha256" | script -qfec \
    "$REVIEW_COMMAND" \
    "$TEMP_DIR/review.log" >/dev/null

for stage in \
        'STAGE 1 OF 6: AUTOMATED VALIDATION' \
        'STAGE 2 OF 6: POLICY AND SCHEMA REVIEW' \
        'STAGE 3 OF 6: RUNTIME SOURCE REVIEW' \
        'STAGE 4 OF 6: GENERATED OUTPUT REVIEW' \
        'STAGE 5 OF 6: INSTALLATION PLAN REVIEW' \
        'STAGE 6 OF 6: FINAL APPROVAL'; do
    grep -Fq "$stage" "$TEMP_DIR/review.log"
done
test "$(grep -Fc '==============================================================================' \
    "$TEMP_DIR/review.log")" -eq 12
test "$(grep -Fc 'Next: Enter/Space, n, Vim, arrows' "$TEMP_DIR/review.log")" -eq 5
test "$(grep -Fc 'Digest entry: Enter/Space, n, Vim, arrows' \
    "$TEMP_DIR/review.log")" -eq 1
grep -Fq 'Ctrl-C: return to Stage 6 navigation' "$TEMP_DIR/review.log"
grep -Fq 'Ctrl-D: abort review' "$TEMP_DIR/review.log"
test "$(grep -Fc 'Integrity revalidation: PASSED' "$TEMP_DIR/review.log")" -eq 1
grep -Fq 'Review complete: exact bundle approval recorded.' "$TEMP_DIR/review.log"
grep -Fq "  $POLICY" "$TEMP_DIR/review.log"
grep -Fq -- '- collectors.yaml' "$TEMP_DIR/review.log"
grep -Fq "  $MODULE_DIR" "$TEMP_DIR/review.log"
grep -Fq -- '- runtime/collect/ai-auditor-inventory.py' "$TEMP_DIR/review.log"
test "$(grep -Fc "  $ARTIFACTS" "$TEMP_DIR/review.log")" -eq 2
grep -Fq -- '- artifact-index.json' "$TEMP_DIR/review.log"
grep -Fq -- '- rootfs/etc/sudoers.d/ai-auditor' "$TEMP_DIR/review.log"
grep -Fq -- '- rootfs/opt/ai-auditor/policy/manifest.json' "$TEMP_DIR/review.log"
grep -Fq 'KIND  MODE  OWNER:GROUP  DESTINATION' "$TEMP_DIR/review.log"
grep -Eq 'FILE +0440 +root:root +/etc/sudoers.d/ai-auditor' \
    "$TEMP_DIR/review.log"
grep -Fq 'sha256sum -- artifact-index.json' "$TEMP_DIR/review.log"
grep -Fq 'Artifact index: artifact-index.json' "$TEMP_DIR/review.log"
grep -Fq "Bundle SHA-256: $bundle_sha256" "$TEMP_DIR/review.log"
test "$(grep -Fc 'Policy SHA-256:' "$TEMP_DIR/review.log")" -eq 1
test "$(grep -Fc 'Bundle SHA-256:' "$TEMP_DIR/review.log")" -eq 1
if grep -Fq 'ai-auditor-cloud ALL=(root:root) NOPASSWD:' "$TEMP_DIR/review.log" \
        || grep -Fq 'collector primitive implementations do not match policy contract' \
        "$TEMP_DIR/review.log" || grep -Fq '  Provenance  :' "$TEMP_DIR/review.log" \
        || grep -Fq 'Reference SHA-256:' "$TEMP_DIR/review.log"; then
    echo "review printed artifact contents instead of concise metadata" >&2
    exit 1
fi

test "$(stat -c %a "$STATE")" = "700"
test "$(stat -c %a "$STATE/policy-approval.json")" = "600"
python3 "$COMPILER" verify --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE" >/dev/null
build_output="$(python3 "$COMPILER" build --policy-dir "$POLICY" \
    --artifacts-dir "$ARTIFACTS" --state-dir "$STATE")"
grep -Fq 'human_approval_status: MATCHED' <<<"$build_output"

cp "$STATE/policy-approval.json" "$TEMP_DIR/approval"
printf 'llllll%s\n' incorrect-digest | script -qfec \
    "$REVIEW_COMMAND" \
    /dev/null >/dev/null 2>&1 || true
cmp "$TEMP_DIR/approval" "$STATE/policy-approval.json"

python3 "$SCRIPT_DIR/test_policy_review_wizard.py" "$MODULE_DIR"

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
