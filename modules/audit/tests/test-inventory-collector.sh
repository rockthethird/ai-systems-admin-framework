#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly POLICY="$SCRIPT_DIR/../deploy/scripts/policy.py"
readonly APP="$SCRIPT_DIR/../deploy/artifacts/rootfs/opt/ai-auditor"
readonly COLLECTOR="$APP/lib/collect.py"
readonly OUTPUT="$(mktemp)"
trap 'rm -f "$OUTPUT"' EXIT

if [ "$(head -n 1 "$COLLECTOR")" != "#!/usr/bin/python3" ]; then
    echo "collector must use the fixed /usr/bin/python3 interpreter" >&2
    exit 1
fi

python3 "$POLICY" build >/dev/null
python3 "$COLLECTOR" > "$OUTPUT"
python3 - "$OUTPUT" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
required = {"schema_version", "collected_at", "limits", "collectors"}
missing = sorted(required - data.keys())
assert not missing, f"missing top-level keys: {missing}"
assert data["schema_version"] == "1.0"
assert data["collectors"]["host-platform"]["items"]["hostname"]
assert isinstance(data["collectors"]["accounts"]["items"], list)
assert len(data["collectors"]["auditor-account-paths"]["items"]) == 2
assert len(data["collectors"]["report-endpoints"]["items"]) == 2
assert data["limits"]["max_bytes_per_stream"] > 0
print("inventory collector test passed")
PY

python3 "$SCRIPT_DIR/test_inventory_collector.py" "$COLLECTOR"

if python3 "$COLLECTOR" unexpected >/dev/null 2>&1; then
    echo "collector unexpectedly accepted an argument" >&2
    exit 1
fi
