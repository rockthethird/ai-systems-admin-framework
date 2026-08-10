#!/usr/bin/python3
"""Convert AI auditor inventory JSON into deterministic findings JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_SCHEMA_VERSION = "ai-auditor-findings/v1"
ENGINE_VERSION = "ai-auditor-static-rules/v1"


def evidence(section: str, path: str, observation: str) -> dict[str, str]:
    return {"section": section, "path": path, "observation": observation}


def finding(identifier: str, title: str, severity: str, category: str,
            evidence_items: list[dict[str, str]], rationale: str, impact: str,
            recommendation: str, confidence: float) -> dict[str, Any]:
    return {
        "id": identifier, "title": title, "severity": severity,
        "category": category, "status": "open", "confidence": confidence,
        "sensitivity": "internal", "evidence": evidence_items,
        "rationale": rationale, "impact": impact,
        "recommendation": recommendation, "references": [],
    }


def filesystem_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    result = inventory.get("filesystems", {})
    items = result.get("items", []) if isinstance(result, dict) else []
    full = []
    for index, line in enumerate(items[1:], start=1):
        columns = line.split()
        if len(columns) < 7 or not re.fullmatch(r"[0-9]+%", columns[-2]):
            continue
        percent = int(columns[-2][:-1])
        if percent >= 90:
            full.append(evidence("filesystems", f"/filesystems/items/{index}",
                                 f"{columns[-1]} is {percent}% utilized"))
    if not full:
        return []
    return [finding(
        "AIA-1001", "Filesystem utilization is at or above 90%", "high",
        "capacity", full,
        "Very high filesystem utilization can exhaust write capacity unexpectedly.",
        "Services may fail to write state, logs, or temporary data.",
        "Confirm growth and retention expectations, then reclaim or add capacity through an approved maintenance workflow.",
        0.98,
    )]


def failed_unit_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    result = inventory.get("systemd", {}).get("failed_units", {})
    items = result.get("items", []) if isinstance(result, dict) else []
    failed = []
    for index, line in enumerate(items):
        lowered = f" {line.lower()} "
        if " failed " in lowered and not line.lstrip().startswith("UNIT "):
            failed.append(evidence("systemd.failed_units", f"/systemd/failed_units/items/{index}", line[:500]))
    if not failed:
        return []
    return [finding(
        "AIA-1002", "Systemd reports failed units", "medium", "service-health",
        failed, "Failed units indicate services that did not reach their requested state.",
        "Required host functionality may be unavailable or degraded.",
        "Confirm whether each unit is required, then inspect status and logs through an approved drill-down collector.",
        0.95,
    )]


def account_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    privileged = []
    for index, account in enumerate(inventory.get("accounts", [])):
        if isinstance(account, dict) and account.get("uid") == 0 and account.get("name") != "root":
            privileged.append(evidence("accounts", f"/accounts/{index}",
                                       f"account {account.get('name', '<unknown>')} has UID 0"))
    if not privileged:
        return []
    return [finding(
        "AIA-1003", "Additional accounts have UID 0", "critical", "identity",
        privileged, "UID 0 accounts have root-equivalent operating-system authority.",
        "Unexpected credentials for these accounts can provide unrestricted host access.",
        "Verify each account's ownership and necessity, then remove or reassign unexpected UID 0 identities through an approved workflow.",
        0.99,
    )]


def collection_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, str]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if "available" in value and path != "/containers":
                if value.get("truncated"):
                    issues.append(evidence("collection", path, "collector output was truncated"))
                if value.get("available") and value.get("error"):
                    issues.append(evidence("collection", path, f"collector error: {str(value['error'])[:300]}"))
                if not value.get("available"):
                    issues.append(evidence("collection", path, "required collector command was unavailable"))
            for key, child in value.items():
                walk(child, f"{path}/{key}" if path else f"/{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}")

    walk(inventory, "")
    if not issues:
        return []
    return [finding(
        "AIA-1004", "Inventory collection was incomplete", "low", "evidence-quality",
        issues, "Missing, failed, or truncated collectors reduce the completeness of the audit evidence.",
        "Other findings may be absent or have lower confidence.",
        "Review collector errors and platform dependencies before treating the audit as complete.",
        1.0,
    )]


def analyze(raw_inventory: bytes) -> dict[str, Any]:
    inventory = json.loads(raw_inventory)
    if inventory.get("schema_version") != "1.0":
        raise ValueError("unsupported inventory schema_version")
    findings = []
    for rule in (filesystem_findings, failed_unit_findings, account_findings, collection_findings):
        findings.extend(rule(inventory))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order[item["severity"]], item["id"]))
    counts = {severity: 0 for severity in order}
    for item in findings:
        counts[item["severity"]] += 1
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "inventory_schema_version": inventory["schema_version"],
            "collected_at": inventory["collected_at"],
            "host": inventory.get("host", {}).get("hostname", "unknown"),
            "inventory_sha256": hashlib.sha256(raw_inventory).hexdigest(),
        },
        "analysis": {
            "engine": ENGINE_VERSION, "model": None,
            "prompt_version": "static-rules/v1",
            "limitations": [
                "Static rules cover only explicitly implemented conditions",
                "No configuration contents or logs were collected",
                "Recommendations require human review and grant no execution authority",
            ],
        },
        "summary": {"total": len(findings), **counts},
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="inventory JSON file")
    parser.add_argument("--output", type=Path, help="write report to this file instead of stdout")
    args = parser.parse_args()
    try:
        report = analyze(args.inventory.read_bytes())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"analysis failed: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
