#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 - "$MODULE_DIR" <<'PY'
import sys
from pathlib import Path
import yaml

module = Path(sys.argv[1])
rules = yaml.safe_load((module / "policy/rules.yaml").read_text())["rules"]
runtime_paths = [
    module / "reporting/analyze-inventory.py",
    module / "reporting/sanitize-findings.py",
    module / "reporting/sanitize-findings-internal.py",
    module / "reporting/sanitize_common.py",
]
runtime = "\n".join(path.read_text() for path in runtime_paths)
for rule in rules:
    for field in ("title", "rationale", "impact", "recommendation"):
        assert rule[field] not in runtime, f"{rule['id']} {field} is duplicated in runtime code"
print("policy review-surface test passed")
PY
