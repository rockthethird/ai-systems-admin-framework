#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly COMPILER="$MODULE_DIR/deploy/scripts/policy.py"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

PYTHONDONTWRITEBYTECODE=1 python3 - "$MODULE_DIR/deploy/scripts" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from policy_support import approval, bundle, review, terminal
assert callable(bundle.build)
assert callable(approval.review)
assert callable(approval.verify)
assert callable(review.run_wizard)
assert callable(terminal.Terminal)
print("policy support imports passed")
PY

build() {
    python3 "$COMPILER" build --policy-dir "$1" --artifacts-dir "$2" >/dev/null
}

build "$MODULE_DIR/deploy/policy" "$TEMP_DIR/first"
build "$MODULE_DIR/deploy/policy" "$TEMP_DIR/second"
diff -r "$TEMP_DIR/first/rootfs" "$TEMP_DIR/second/rootfs"
cmp "$TEMP_DIR/first/artifact-index.json" "$TEMP_DIR/second/artifact-index.json"

python3 - "$TEMP_DIR/first" "$MODULE_DIR" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

artifacts = Path(sys.argv[1])
module = Path(sys.argv[2])
index_bytes = (artifacts / "artifact-index.json").read_bytes()
index = json.loads(index_bytes)
manifest = json.loads((artifacts / "rootfs/opt/ai-auditor/policy/manifest.json").read_bytes())

assert set(manifest) == {"version", "collectors", "rules", "profiles", "identities"}
ids = {item["id"] for item in manifest["collectors"]["collectors"]}
assert ids == {
    "host-uptime", "filesystems", "network-interfaces", "network-routes",
    "network-listening-sockets", "systemd-failed-units", "systemd-timers",
    "systemd-enabled-units", "packages", "containers", "accounts",
    "ssh-effective-settings", "auditor-account-paths", "report-endpoints",
    "host-platform", "os-release", "scheduled-task-paths",
}
identities = manifest["identities"]["identities"]
profiles = {item["id"]: item for item in manifest["profiles"]["profiles"]}
assert profiles == {
    "external-safe/v1": {
        "id": "external-safe/v1",
        "schema": "ai-auditor-external-findings/v1",
        "evidence": "count-and-section",
    },
    "internal-rich/v1": {
        "id": "internal-rich/v1",
        "schema": "ai-auditor-internal-findings/v1",
        "evidence": "approved-internal-summary",
    },
}
identity_users = sorted(item["user"] for item in identities)
identity_endpoints = sorted(item["endpoint"] for item in identities)
collectors = {item["id"]: item for item in manifest["collectors"]["collectors"]}
assert collectors["ssh-effective-settings"]["parameters"]["users"] == identity_users
assert collectors["auditor-account-paths"]["parameters"]["users"] == identity_users
assert collectors["report-endpoints"]["primitive"] == "identity-endpoint-metadata"
assert collectors["report-endpoints"]["parameters"]["paths"] == identity_endpoints

assert index["schema_version"] == "ai-auditor-artifact-index/v1"
assert [item["destination"] for item in index["entries"]] == sorted(
    item["destination"] for item in index["entries"]
)
for item in index["entries"]:
    path = artifacts / item["bundle_path"]
    assert path.is_dir() if item["kind"] == "directory" else path.is_file()
    if item["kind"] == "file":
        assert ("source" in item) != ("generated" in item)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
files = {item["id"]: item for item in index["entries"] if item["kind"] == "file"}
external = artifacts / files["report-external"]["bundle_path"]
internal = artifacts / files["report-internal"]["bundle_path"]
assert external.read_text().endswith(
    "exec /opt/ai-auditor/lib/report external-safe/v1\n")
assert internal.read_text().endswith(
    "exec /opt/ai-auditor/lib/report internal-rich/v1\n")
assert "$@" not in external.read_text() + internal.read_text()
assert files["report-external"]["sha256"] != files["report-internal"]["sha256"]
report_runner = artifacts / files["report-runner"]["bundle_path"]
assert report_runner.read_bytes() == (
    module / "runtime/reporting/ai-auditor-report.sh").read_bytes()
collector_policy = artifacts / "rootfs/opt/ai-auditor/lib/collector_policy.py"
assert collector_policy.read_bytes() == (module / "runtime/collect/collector_policy.py").read_bytes()
assert files["collector-policy"]["sha256"] == hashlib.sha256(
    collector_policy.read_bytes()).hexdigest()
print("deterministic policy bundle passed")
PY

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/derived-identity"
python3 - "$TEMP_DIR/derived-identity/identities.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace("ai-auditor-cloud", "ai-auditor-edge"))
PY
build "$TEMP_DIR/derived-identity" "$TEMP_DIR/derived-identity-artifacts"
python3 - "$TEMP_DIR/derived-identity-artifacts" <<'PY'
import json
import sys
from pathlib import Path
artifacts = Path(sys.argv[1])
manifest = json.loads(
    (artifacts / "rootfs/opt/ai-auditor/policy/manifest.json").read_text())
collectors = {item["id"]: item for item in manifest["collectors"]["collectors"]}
users = collectors["auditor-account-paths"]["parameters"]["users"]
assert users == ["ai-auditor-edge", "ai-auditor-local"]
sudoers = (artifacts / "rootfs/etc/sudoers.d/ai-auditor").read_text()
assert "ai-auditor-edge ALL=" in sudoers
assert "ai-auditor-cloud ALL=" not in sudoers
print("identity-derived collector policy passed")
PY

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/profile-mismatch"
python3 - "$TEMP_DIR/profile-mismatch/profiles.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace(
    "evidence: count-and-section", "evidence: approved-internal-summary", 1))
PY
if build "$TEMP_DIR/profile-mismatch" "$TEMP_DIR/profile-mismatch-artifacts" 2>/dev/null; then
    echo "compiler accepted a profile that does not match its runtime contract" >&2
    exit 1
fi

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/unsafe-collector"
python3 - "$TEMP_DIR/unsafe-collector/collectors.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace("        - /etc/crontab", "        - ../etc/crontab", 1))
PY
if build "$TEMP_DIR/unsafe-collector" "$TEMP_DIR/unsafe-collector-artifacts" 2>/dev/null; then
    echo "compiler accepted an unsafe built-in collector path" >&2
    exit 1
fi

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/duplicate"
python3 - "$TEMP_DIR/duplicate/rules.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace("  - id: AIA-1002", "  - id: AIA-1001", 1))
PY
if build "$TEMP_DIR/duplicate" "$TEMP_DIR/duplicate-artifacts" 2>/dev/null; then
    echo "compiler accepted a duplicate rule ID" >&2
    exit 1
fi

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/unexpected"
printf 'version: ignored/v1\n' > "$TEMP_DIR/unexpected/ignored.yaml"
if build "$TEMP_DIR/unexpected" "$TEMP_DIR/unexpected-artifacts" 2>/dev/null; then
    echo "compiler accepted an undeclared policy file" >&2
    exit 1
fi

if PATH=/usr/bin python3 "$COMPILER" build \
        --policy-dir "$MODULE_DIR/deploy/policy" \
        --artifacts-dir "$TEMP_DIR/no-visudo" >/dev/null 2>&1; then
    echo "compiler succeeded without visudo" >&2
    exit 1
fi

echo "policy compilation tests passed"
