#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly COMPILER="$MODULE_DIR/deploy/scripts/policy.py"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

build() {
    python3 "$COMPILER" build --policy-dir "$1" --artifacts-dir "$2" >/dev/null
}

build "$MODULE_DIR/deploy/policy" "$TEMP_DIR/first"
build "$MODULE_DIR/deploy/policy" "$TEMP_DIR/second"
cmp "$TEMP_DIR/first/policy-manifest.json" "$TEMP_DIR/second/policy-manifest.json"
cmp "$TEMP_DIR/first/sudoers-ai-auditor" "$TEMP_DIR/second/sudoers-ai-auditor"
cmp "$TEMP_DIR/first/artifact-index.json" "$TEMP_DIR/second/artifact-index.json"

python3 - "$TEMP_DIR/first" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

artifacts = Path(sys.argv[1])
index_bytes = (artifacts / "artifact-index.json").read_bytes()
index = json.loads(index_bytes)
manifest = json.loads((artifacts / "policy-manifest.json").read_bytes())

assert set(manifest) == {"version", "collectors", "rules", "profiles", "identities"}
ids = {item["id"] for item in manifest["collectors"]["collectors"]}
assert ids == {
    "host-uptime", "filesystems", "network-interfaces", "network-routes",
    "network-listening-sockets", "systemd-failed-units", "systemd-timers",
    "systemd-enabled-units", "packages", "containers", "accounts",
    "ssh-effective-settings", "auditor-account-paths", "report-endpoints",
}

assert index["schema_version"] == "ai-auditor-artifact-index/v1"
assert [item["destination"] for item in index["artifacts"]] == sorted(
    item["destination"] for item in index["artifacts"]
)
for item in index["artifacts"]:
    content = (artifacts / item["file"]).read_bytes()
    assert hashlib.sha256(content).hexdigest() == item["sha256"]
print("deterministic policy bundle passed")
PY

cp -a "$MODULE_DIR/deploy/policy" "$TEMP_DIR/unsafe"
python3 - "$TEMP_DIR/unsafe/profiles.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace("      - raw-inventory\n", "", 1))
PY
if build "$TEMP_DIR/unsafe" "$TEMP_DIR/unsafe-artifacts" 2>/dev/null; then
    echo "compiler accepted weakened external disclosure" >&2
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
