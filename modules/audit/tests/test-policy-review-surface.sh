#!/bin/bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly MODULE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 - "$MODULE_DIR" <<'PY'
import sys
from pathlib import Path
import yaml

module = Path(sys.argv[1])
rules = yaml.safe_load((module / "deploy/policy/rules.yaml").read_text())["rules"]
runtime_paths = [
    module / "runtime/reporting/analyze-inventory.py",
    module / "runtime/reporting/sanitize-findings.py",
    module / "runtime/reporting/sanitize-findings-internal.py",
    module / "runtime/reporting/sanitize_common.py",
]
runtime = "\n".join(path.read_text() for path in runtime_paths)
for rule in rules:
    for field in ("title", "rationale", "impact", "recommendation"):
        assert rule[field] not in runtime, f"{rule['id']} {field} is duplicated in runtime code"
collector_policy = yaml.safe_load((module / "deploy/policy/collectors.yaml").read_text())
collector_runtime = (module / "runtime/collect/ai-auditor-inventory.py").read_text()
for collector in collector_policy["collectors"]:
    for candidate in collector.get("candidates", []):
        rendered = repr([candidate["path"], *candidate["args"]])
        assert rendered not in collector_runtime, f"{collector['id']} command is duplicated in runtime"
print("policy review-surface test passed")
PY
