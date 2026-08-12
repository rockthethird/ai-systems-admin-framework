#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly COLLECTOR="$SCRIPT_DIR/../runtime/collect/ai-auditor-inventory.py"
readonly OUTPUT="$(mktemp)"
trap 'rm -f "$OUTPUT"' EXIT

if [ "$(head -n 1 "$COLLECTOR")" != "#!/usr/bin/python3" ]; then
    echo "collector must use the fixed /usr/bin/python3 interpreter" >&2
    exit 1
fi

python3 "$COLLECTOR" > "$OUTPUT"
python3 - "$OUTPUT" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
required = {"schema_version", "collected_at", "limits", "host", "filesystems", "network", "systemd", "accounts", "packages", "containers", "scheduled_tasks", "security"}
missing = sorted(required - data.keys())
assert not missing, f"missing top-level keys: {missing}"
assert data["schema_version"] == "1.0"
assert data["host"]["hostname"]
assert isinstance(data["accounts"], list)
assert set(data["security"]) == {"ssh", "auditor_accounts", "report_endpoints"}
assert len(data["security"]["auditor_accounts"]) == 2
assert len(data["security"]["report_endpoints"]) == 2
assert data["limits"]["max_bytes_per_stream"] > 0
print("inventory collector test passed")
PY

python3 "$SCRIPT_DIR/test_inventory_collector.py"

if python3 "$COLLECTOR" unexpected >/dev/null 2>&1; then
    echo "collector unexpectedly accepted an argument" >&2
    exit 1
fi
