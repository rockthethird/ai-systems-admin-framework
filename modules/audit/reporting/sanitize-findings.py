#!/usr/bin/python3
"""Create a minimized external-model view of deterministic findings JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

INPUT_SCHEMA = "ai-auditor-findings/v1"
OUTPUT_SCHEMA = "ai-auditor-external-findings/v1"
PROFILE = "external-safe/v1"
TRUSTED_ENGINE = "ai-auditor-static-rules/v1"
SEVERITIES = ("critical", "high", "medium", "low", "info")
SAFE_SECTIONS = {
    "accounts", "collection", "filesystems", "systemd.failed_units",
}

# Public text is reconstructed rather than copied from the input report. This
# prevents host-controlled evidence or a modified report from becoming model
# instructions through an otherwise allowlisted string field.
PUBLIC_RULES = {
    "AIA-1001": {
        "title": "Filesystem utilization is at or above 90%",
        "severity": "high",
        "category": "capacity",
        "rationale": "Very high filesystem utilization can exhaust write capacity unexpectedly.",
        "impact": "Services may fail to write state, logs, or temporary data.",
        "recommendation": "Confirm growth and retention expectations, then reclaim or add capacity through an approved maintenance workflow.",
    },
    "AIA-1002": {
        "title": "Systemd reports failed units",
        "severity": "medium",
        "category": "service-health",
        "rationale": "Failed units indicate services that did not reach their requested state.",
        "impact": "Required host functionality may be unavailable or degraded.",
        "recommendation": "Confirm whether each unit is required, then inspect status and logs through an approved drill-down collector.",
    },
    "AIA-1003": {
        "title": "Additional accounts have UID 0",
        "severity": "critical",
        "category": "identity",
        "rationale": "UID 0 accounts have root-equivalent operating-system authority.",
        "impact": "Unexpected credentials for these accounts can provide unrestricted host access.",
        "recommendation": "Verify each account's ownership and necessity, then remove or reassign unexpected UID 0 identities through an approved workflow.",
    },
    "AIA-1004": {
        "title": "Inventory collection was incomplete",
        "severity": "low",
        "category": "evidence-quality",
        "rationale": "Missing, failed, or truncated collectors reduce the completeness of the audit evidence.",
        "impact": "Other findings may be absent or have lower confidence.",
        "recommendation": "Review collector errors and platform dependencies before treating the audit as complete.",
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sanitize_assessment(report: dict[str, Any], failed_ids: set[str]) -> dict[str, Any]:
    assessment = report.get("assessment")
    require(isinstance(assessment, dict), "assessment must be an object")
    results = assessment.get("results")
    require(isinstance(results, list) and len(results) == len(PUBLIC_RULES),
            "assessment must cover every supported rule")
    safe_results = []
    seen = set()
    counts = {status: 0 for status in ("passed", "failed", "unknown")}
    for result in results:
        require(isinstance(result, dict), "assessment result must be an object")
        identifier = result.get("id")
        require(identifier in PUBLIC_RULES and identifier not in seen,
                f"unsupported or duplicate assessment rule: {identifier}")
        seen.add(identifier)
        status = result.get("status")
        require(status in counts, f"assessment rule {identifier} has invalid status")
        require((status == "failed") == (identifier in failed_ids),
                f"assessment rule {identifier} disagrees with findings")
        control = result.get("control")
        section = result.get("section")
        require(isinstance(control, str) and control and isinstance(section, str) and section,
                f"assessment rule {identifier} has invalid metadata")
        counts[status] += 1
        safe_results.append({"id": identifier, "control": control, "section": section, "status": status})
    require(seen == set(PUBLIC_RULES), "assessment omits supported rules")
    require(assessment.get("rules_evaluated") == len(results) and
            all(assessment.get(status) == count for status, count in counts.items()),
            "assessment counts do not match results")
    return {"rules_evaluated": len(results), **counts, "results": safe_results}


def sanitize(raw_report: bytes) -> dict[str, Any]:
    report = json.loads(raw_report)
    require(isinstance(report, dict), "findings report must be an object")
    require(report.get("schema_version") == INPUT_SCHEMA, "unsupported findings schema_version")
    analysis = report.get("analysis")
    require(isinstance(analysis, dict), "analysis must be an object")
    require(analysis.get("engine") == TRUSTED_ENGINE, "external-safe profile requires the trusted static engine")
    findings = report.get("findings")
    require(isinstance(findings, list), "findings must be an array")

    safe_findings = []
    counts = {severity: 0 for severity in SEVERITIES}
    withheld_items = 0
    seen = set()
    degraded = False
    for item in findings:
        require(isinstance(item, dict), "finding must be an object")
        identifier = item.get("id")
        require(identifier in PUBLIC_RULES, f"unsupported finding id: {identifier}")
        require(identifier not in seen, f"duplicate finding id: {identifier}")
        seen.add(identifier)
        public = PUBLIC_RULES[identifier]
        for field in ("title", "severity", "category", "rationale", "impact", "recommendation"):
            require(item.get(field) == public[field], f"finding {identifier} has unexpected {field}")
        status = item.get("status")
        confidence = item.get("confidence")
        evidence = item.get("evidence")
        require(status in {"open", "accepted", "resolved", "not_applicable"}, f"finding {identifier} has invalid status")
        require(isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and 0 <= confidence <= 1,
                f"finding {identifier} has invalid confidence")
        require(isinstance(evidence, list) and evidence, f"finding {identifier} has no evidence")
        sections = set()
        for evidence_item in evidence:
            require(isinstance(evidence_item, dict), f"finding {identifier} has invalid evidence")
            section = evidence_item.get("section")
            sections.add(section if section in SAFE_SECTIONS else "other")
        withheld_items += len(evidence)
        counts[public["severity"]] += 1
        degraded = degraded or identifier == "AIA-1004"
        safe_findings.append({
            "id": identifier,
            **public,
            "status": status,
            "confidence": confidence,
            "evidence": {
                "observation_count": len(evidence),
                "sections": sorted(sections),
                "details": "withheld",
            },
        })

    expected_summary = {"total": len(safe_findings), **counts}
    require(report.get("summary") == expected_summary, "findings summary does not match findings")
    source = report.get("source")
    require(isinstance(source, dict), "source must be an object")
    inventory_digest = source.get("inventory_sha256")
    require(isinstance(inventory_digest, str) and len(inventory_digest) == 64 and
            all(character in "0123456789abcdef" for character in inventory_digest),
            "source inventory_sha256 is invalid")
    safe_assessment = sanitize_assessment(report, seen)

    return {
        "schema_version": OUTPUT_SCHEMA,
        "profile": PROFILE,
        "source": {
            "input_schema_version": INPUT_SCHEMA,
            "inventory_sha256": inventory_digest,
            "findings_sha256": hashlib.sha256(raw_report).hexdigest(),
        },
        "disclosure": {
            "raw_inventory_included": False,
            "host_identifiers_included": False,
            "collection_timestamps_included": False,
            "evidence_paths_included": False,
            "evidence_observations_included": False,
            "withheld_evidence_items": withheld_items,
        },
        "evidence_quality": "degraded" if degraded else "complete",
        "analysis": {
            "engine": TRUSTED_ENGINE,
            "model": None,
            "limitations": [
                "Only deterministic rules explicitly supported by external-safe/v1 are included",
                "Host identifiers, collection times, evidence paths, and observations are withheld",
                "Recommendations require human review and grant no execution authority",
            ],
        },
        "assessment": safe_assessment,
        "summary": expected_summary,
        "findings": safe_findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings", type=Path, help="deterministic findings JSON file")
    parser.add_argument("--output", type=Path, help="write sanitized JSON to this file instead of stdout")
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
