#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly COMPILER="$MODULE_DIR/build/compile-policy.py"
readonly TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

python3 "$COMPILER" --check
python3 "$COMPILER" --output "$TEMP_DIR/manifest.json"
cmp "$MODULE_DIR/generated/policy-manifest.json" "$TEMP_DIR/manifest.json"

python3 - "$TEMP_DIR/manifest.json" <<'PY'
import json
import sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
ids = {item["id"] for item in manifest["collectors"]["collectors"]}
assert ids == {
    "host-uptime", "filesystems", "network-interfaces", "network-routes",
    "network-listening-sockets", "systemd-failed-units", "systemd-timers",
    "systemd-enabled-units", "packages", "containers", "accounts",
    "ssh-effective-settings", "auditor-account-paths", "report-endpoints",
}
print("collector policy coverage passed")
PY

cp -a "$MODULE_DIR/policy" "$TEMP_DIR/policy"
python3 - "$TEMP_DIR/policy/profiles.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
path.write_text(path.read_text().replace("      - raw-inventory\n", "", 1))
PY
if python3 "$COMPILER" --policy-dir "$TEMP_DIR/policy" --output "$TEMP_DIR/unsafe.json" >/dev/null 2>&1; then
    echo "compiler accepted weakened external disclosure" >&2
    exit 1
fi

cp -a "$MODULE_DIR/policy" "$TEMP_DIR/duplicate"
python3 - "$TEMP_DIR/duplicate/rules.yaml" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text()
path.write_text(text.replace("  - id: AIA-1002", "  - id: AIA-1001", 1))
PY
if python3 "$COMPILER" --policy-dir "$TEMP_DIR/duplicate" --output "$TEMP_DIR/duplicate.json" >/dev/null 2>&1; then
    echo "compiler accepted a duplicate rule ID" >&2
    exit 1
fi

echo "policy compilation tests passed"
