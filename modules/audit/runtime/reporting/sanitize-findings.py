#!/usr/bin/python3
"""Create a minimized external-model view of deterministic findings JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from audit_policy import PROFILES, RULES
from sanitize_common import require, sanitize_findings

INPUT_SCHEMA = "ai-auditor-findings/v1"
PROFILE = "external-safe/v1"
PROFILE_POLICY = PROFILES[PROFILE]
OUTPUT_SCHEMA = PROFILE_POLICY["schema"]
TRUSTED_ENGINE = "ai-auditor-static-rules/v1"
if PROFILE_POLICY["evidence"] != "count-and-section":
    raise ValueError("external-safe profile requires count-and-section evidence")


def external_evidence(identifier: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    sections = set()
    expected_section = RULES[identifier]["section"]
    for item in evidence:
        require(isinstance(item, dict), f"finding {identifier} has invalid evidence")
        section = item.get("section")
        require(section == expected_section,
                f"finding {identifier} has evidence outside its declared section")
        sections.add(section)
    return {"observation_count": len(evidence), "sections": sorted(sections), "details": "withheld"}


def sanitize(raw_report: bytes) -> dict[str, Any]:
    report = json.loads(raw_report)
    require(isinstance(report, dict), "findings report must be an object")
    require(report.get("schema_version") == INPUT_SCHEMA, "unsupported findings schema_version")
    analysis = report.get("analysis")
    require(isinstance(analysis, dict) and analysis.get("engine") == TRUSTED_ENGINE,
            "external-safe profile requires the trusted static engine")
    safe_findings, summary, assessment, degraded = sanitize_findings(report, external_evidence)
    source = report.get("source")
    require(isinstance(source, dict), "source must be an object")
    digest = source.get("inventory_sha256")
    require(isinstance(digest, str) and len(digest) == 64 and
            all(character in "0123456789abcdef" for character in digest),
            "source inventory_sha256 is invalid")
    return {
        "schema_version": OUTPUT_SCHEMA, "profile": PROFILE,
        "source": {"input_schema_version": INPUT_SCHEMA, "inventory_sha256": digest,
                   "findings_sha256": hashlib.sha256(raw_report).hexdigest()},
        "disclosure": {"raw_inventory_included": False, "host_identifiers_included": False,
                       "collection_timestamps_included": False, "evidence_paths_included": False,
                       "evidence_observations_included": False,
                       "withheld_evidence_items": sum(len(item["evidence"]) for item in report["findings"])},
        "evidence_quality": "degraded" if degraded else "complete",
        "analysis": {"engine": TRUSTED_ENGINE, "model": None, "limitations": [
            "Only deterministic rules explicitly supported by external-safe/v1 are included",
            "Host identifiers, collection times, evidence paths, and observations are withheld",
            "Recommendations require human review and grant no execution authority"]},
        "assessment": assessment, "summary": summary, "findings": safe_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        rendered = json.dumps(sanitize(args.findings.read_bytes()), indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"sanitization failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
