#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly SCHEMA="$MODULE_DIR/reporting/schema/ai-auditor-findings-v1.schema.json"
readonly EXAMPLE="$MODULE_DIR/reporting/examples/findings-v1.example.json"

/usr/bin/python3 - "$SCHEMA" "$EXAMPLE" <<'PY'
import json
import re
import sys
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))

try:
    import jsonschema
except ImportError:
    jsonschema = None

if jsonschema is not None:
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(report)

assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
assert schema["properties"]["schema_version"]["const"] == "ai-auditor-findings/v1"
assert schema["additionalProperties"] is False
assert report["schema_version"] == "ai-auditor-findings/v1"
assert report["source"]["inventory_schema_version"] == "1.0"
assert re.fullmatch(r"[a-f0-9]{64}", report["source"]["inventory_sha256"])

severities = ("critical", "high", "medium", "low", "info")
counts = {severity: 0 for severity in severities}
identifiers = set()
for finding in report["findings"]:
    assert re.fullmatch(r"AIA-[0-9]{4}", finding["id"])
    assert finding["id"] not in identifiers
    identifiers.add(finding["id"])
    assert finding["severity"] in severities
    assert 0 <= finding["confidence"] <= 1
    assert finding["evidence"]
    assert all(item["path"].startswith("/") for item in finding["evidence"])
    counts[finding["severity"]] += 1

assert report["summary"]["total"] == len(report["findings"])
assert all(report["summary"][severity] == counts[severity] for severity in severities)
print("findings schema example validated")
PY
