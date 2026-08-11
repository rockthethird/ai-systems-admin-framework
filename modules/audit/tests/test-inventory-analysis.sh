#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly INVENTORY="$(mktemp)"
readonly REPORT="$(mktemp)"
trap 'rm -f "$INVENTORY" "$REPORT"' EXIT

/usr/bin/python3 - "$INVENTORY" <<'PY'
import json
import sys

command = {"available": True, "items": [], "truncated": False, "exit_code": 0, "error": None}
inventory = {
    "schema_version": "1.0",
    "collected_at": "2026-08-10T18:00:00Z",
    "host": {"hostname": "analysis-test"},
    "filesystems": {**command, "items": [
        "Filesystem Type 1024-blocks Used Available Capacity Mounted on",
        "/dev/test ext4 100 95 5 95% /full",
    ]},
    "systemd": {"failed_units": {**command, "items": [
        "example.service loaded failed failed Example service",
    ]}},
    "accounts": [
        {"name": "root", "uid": 0},
        {"name": "unexpected-admin", "uid": 0},
    ],
    "packages": {**command, "truncated": True},
    "containers": {"available": False, "items": [], "truncated": False, "exit_code": None, "error": "command not found"},
}
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(inventory, stream)
PY

/usr/bin/python3 "$MODULE_DIR/reporting/analyze-inventory.py" "$INVENTORY" --output "$REPORT"

/usr/bin/python3 - "$MODULE_DIR/reporting/schema/ai-auditor-findings-v1.schema.json" "$REPORT" <<'PY'
import json
import sys
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
assert [item["id"] for item in report["findings"]] == ["AIA-1003", "AIA-1001", "AIA-1002", "AIA-1004"]
assert report["summary"] == {"total": 4, "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0}
assert report["source"]["host"] == "analysis-test"
assert report["analysis"]["model"] is None
assert report["assessment"]["rules_evaluated"] == 4
assert report["assessment"]["passed"] == 0
assert report["assessment"]["failed"] == 4
assert report["assessment"]["unknown"] == 0
assert {item["id"]: item["status"] for item in report["assessment"]["results"]} == {
    "AIA-1001": "failed", "AIA-1002": "failed", "AIA-1003": "failed", "AIA-1004": "failed",
}

try:
    import jsonschema
except ImportError:
    pass
else:
    jsonschema.Draft202012Validator(schema).validate(report)
print("inventory analysis test passed")
PY

if /usr/bin/python3 "$MODULE_DIR/reporting/analyze-inventory.py" /dev/null >/dev/null 2>&1; then
    echo "analyzer unexpectedly accepted invalid inventory" >&2
    exit 1
fi
