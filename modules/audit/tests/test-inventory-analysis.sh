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
    "security": {
        "ssh": {"available": True, "users": [{"name": "ai-auditor-cloud", "available": True, "settings": {"passwordauthentication": "yes", "kbdinteractiveauthentication": "no", "permitrootlogin": "prohibit-password"}}], "error": None},
        "auditor_accounts": [{"name": "ai-auditor-cloud", "exists": True, "uid": 996, "shell": "/bin/bash", "home": "/opt/ai-auditor-cloud", "home_metadata": {"exists": True, "mode": "0o777", "uid": 996}, "authorized_keys_metadata": {"exists": False}}],
        "report_endpoints": [{"path": "/usr/local/libexec/ai-auditor-report", "exists": True, "mode": "0o775", "uid": 1000, "gid": 1000}],
    },
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
assert [item["id"] for item in report["findings"]] == ["AIA-1003", "AIA-1104", "AIA-1001", "AIA-1101", "AIA-1105", "AIA-1002", "AIA-1102", "AIA-1103", "AIA-1004"]
assert report["summary"] == {"total": 9, "critical": 2, "high": 3, "medium": 3, "low": 1, "info": 0}
assert report["source"]["host"] == "analysis-test"
assert report["analysis"]["model"] is None
assert report["assessment"]["rules_evaluated"] == 9
assert report["assessment"]["passed"] == 0
assert report["assessment"]["failed"] == 9
assert report["assessment"]["unknown"] == 0
statuses = {item["id"]: item["status"] for item in report["assessment"]["results"]}
assert all(status == "failed" for status in statuses.values())

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
