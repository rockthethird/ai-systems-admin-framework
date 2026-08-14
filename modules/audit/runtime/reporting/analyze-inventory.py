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

sys.dont_write_bytecode = True

from audit_policy import RULES as POLICY_RULES

REPORT_SCHEMA_VERSION = "ai-auditor-findings/v1"
ENGINE_VERSION = "ai-auditor-static-rules/v1"
RULES = tuple(POLICY_RULES.values())


def evidence(section: str, path: str, observation: str) -> dict[str, str]:
    return {"section": section, "path": path, "observation": observation}


def finding(identifier: str, evidence_items: list[dict[str, str]]) -> dict[str, Any]:
    rule = POLICY_RULES[identifier]
    return {
        "id": identifier, "title": rule["title"], "severity": rule["severity"],
        "category": rule["category"], "status": "open", "confidence": rule["confidence"],
        "sensitivity": "internal", "evidence": evidence_items,
        "rationale": rule["rationale"], "impact": rule["impact"],
        "recommendation": rule["recommendation"], "references": [],
    }


def collector(inventory: dict[str, Any], identifier: str) -> dict[str, Any]:
    result = inventory.get("collectors", {}).get(identifier, {})
    return result if isinstance(result, dict) else {}


def items(inventory: dict[str, Any], identifier: str) -> Any:
    return collector(inventory, identifier).get("items")


def filesystem_threshold(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    result = collector(inventory, rule["source"])
    items = result.get("items", []) if isinstance(result, dict) else []
    full = []
    for index, line in enumerate(items[1:], start=1):
        columns = line.split()
        if len(columns) < 7 or not re.fullmatch(r"[0-9]+%", columns[-2]):
            continue
        percent = int(columns[-2][:-1])
        if percent >= 90:
            full.append(evidence(rule["section"], f"/filesystems/items/{index}",
                                 f"{columns[-1]} is {percent}% utilized"))
    return full


def systemd_failed_units(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    result = collector(inventory, rule["source"])
    items = result.get("items", []) if isinstance(result, dict) else []
    failed = []
    for index, line in enumerate(items):
        lowered = f" {line.lower()} "
        if " failed " in lowered and not line.lstrip().startswith("UNIT "):
            failed.append(evidence(rule["section"], f"/systemd/failed_units/items/{index}", line[:500]))
    return failed


def additional_uid_zero_accounts(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    privileged = []
    accounts = items(inventory, rule["source"])
    for index, account in enumerate(accounts if isinstance(accounts, list) else []):
        if isinstance(account, dict) and account.get("uid") == 0 and account.get("name") != "root":
            privileged.append(evidence(rule["section"], f"/accounts/{index}",
                                       f"account {account.get('name', '<unknown>')} has UID 0"))
    return privileged


def inventory_completeness(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []

    collectors = inventory.get("collectors", {})
    for identifier, result in collectors.items() if isinstance(collectors, dict) else []:
        if not isinstance(result, dict) or result.get("required") is not True:
            continue
        path = f"/collectors/{identifier}"
        if result.get("truncated"):
            issues.append(evidence(rule["section"], path, "collector output was truncated"))
        if result.get("available") and result.get("error"):
            issues.append(evidence(rule["section"], path,
                                   f"collector error: {str(result['error'])[:300]}"))
        if not result.get("available"):
            issues.append(evidence(rule["section"], path,
                                   "required collector command was unavailable"))
    return issues


def ssh_password_authentication(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    users = items(inventory, rule["source"])
    result = []
    for index, user in enumerate(users if isinstance(users, list) else []):
        settings = user.get("settings", {}) if isinstance(user, dict) else {}
        name = user.get("name", "unknown") if isinstance(user, dict) else "unknown"
        if settings.get("passwordauthentication") != "no" or settings.get("kbdinteractiveauthentication") != "no":
            result.append(evidence(rule["section"], f"/security/ssh/users/{index}/settings",
                                     f"password-capable SSH authentication is enabled for {name}"))
    return result


def ssh_root_login(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    result = []
    for index, user in enumerate(items(inventory, rule["source"]) or []):
        settings = user.get("settings", {}) if isinstance(user, dict) else {}
        if settings.get("permitrootlogin") != "no":
            result.append(evidence(rule["section"], f"/security/ssh/users/{index}/settings/permitrootlogin",
                                   f"PermitRootLogin is {settings.get('permitrootlogin', 'unknown')}"))
    return result


def auditor_interactive_shell(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    shells = []
    for index, account in enumerate(items(inventory, rule["source"]) or []):
        if (isinstance(account, dict) and account.get("exists")
                and account.get("shell") not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}):
            shells.append(evidence(rule["section"],
                                   f"/security/auditor_accounts/{index}/shell",
                                   f"auditor account {account.get('name', 'unknown')} uses an interactive shell"))
    return shells


def auditor_path_permissions(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    paths = []
    for index, account in enumerate(items(inventory, rule["source"]) or []):
        if not isinstance(account, dict):
            continue
        if not account.get("exists"):
            paths.append(evidence(rule["section"], f"/security/auditor_accounts/{index}",
                                  f"auditor account {account.get('name', 'unknown')} is missing"))
            continue
        expected_uid = account.get("uid")
        home = account.get("home_metadata") or {}
        authorized = account.get("paths", {}).get(".ssh/authorized_keys") or {}
        try:
            home_mode = int(str(home.get("mode")), 8)
        except (TypeError, ValueError):
            home_mode = -1
        if not home.get("exists") or home.get("uid") != expected_uid or home_mode < 0 or home_mode & 0o022:
            paths.append(evidence(rule["section"], f"/security/auditor_accounts/{index}/home_metadata",
                                  f"auditor account {account.get('name', 'unknown')} home ownership or mode is unsafe"))
        if authorized.get("exists"):
            try:
                key_mode = int(str(authorized.get("mode")), 8)
            except (TypeError, ValueError):
                key_mode = -1
            if authorized.get("uid") != expected_uid or key_mode < 0 or key_mode & 0o077:
                paths.append(evidence(rule["section"], f"/security/auditor_accounts/{index}/authorized_keys_metadata",
                                      f"auditor account {account.get('name', 'unknown')} authorized_keys ownership or mode is unsafe"))
    return paths


def report_endpoint_integrity(rule: dict[str, Any], inventory: dict[str, Any]) -> list[dict[str, str]]:
    endpoints = items(inventory, rule["source"])
    unsafe = []
    for index, endpoint in enumerate(endpoints if isinstance(endpoints, list) else []):
        if not isinstance(endpoint, dict):
            continue
        try:
            mode = int(str(endpoint.get("mode")), 8)
        except (TypeError, ValueError):
            mode = -1
        if not endpoint.get("exists") or endpoint.get("uid") != 0 or endpoint.get("gid") != 0 or mode < 0 or mode & 0o022:
            unsafe.append(evidence(rule["section"], f"/security/report_endpoints/{index}",
                                   "a report endpoint is missing, not root-owned, or writable by non-root"))
    return unsafe


EVALUATORS = {
    "filesystem-threshold": filesystem_threshold,
    "systemd-failed-units": systemd_failed_units,
    "additional-uid-zero-accounts": additional_uid_zero_accounts,
    "inventory-completeness": inventory_completeness,
    "ssh-password-authentication": ssh_password_authentication,
    "ssh-root-login": ssh_root_login,
    "auditor-interactive-shell": auditor_interactive_shell,
    "report-endpoint-integrity": report_endpoint_integrity,
    "auditor-path-permissions": auditor_path_permissions,
}


def validate_evaluators() -> None:
    declared = {rule["evaluator"] for rule in RULES}
    if declared != set(EVALUATORS):
        raise ValueError(f"evaluator registry does not match policy; "
                         f"missing={sorted(declared - set(EVALUATORS))}, "
                         f"unused={sorted(set(EVALUATORS) - declared)}")


def result_available(value: Any) -> bool:
    return (isinstance(value, dict) and value.get("available") is True
            and value.get("truncated") is False and not value.get("error"))


def assessment(findings: list[dict[str, Any]], inventory: dict[str, Any]) -> dict[str, Any]:
    failed = {item["id"] for item in findings}
    results = []
    for rule in RULES:
        identifier = rule["id"]
        source = rule["source"]
        available = (True if source == "all-required-collectors"
                     else result_available(collector(inventory, source)))
        status = "failed" if identifier in failed else ("passed" if available else "unknown")
        results.append({"id": identifier, "control": rule["control"], "section": rule["section"],
                        "status": status, "summary": rule["passed"] if status == "passed" else None})
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("passed", "failed", "unknown")}
    return {"rules_evaluated": len(results), **counts, "results": results}


def analyze(raw_inventory: bytes) -> dict[str, Any]:
    inventory = json.loads(raw_inventory)
    if inventory.get("schema_version") != "1.0":
        raise ValueError("unsupported inventory schema_version")
    validate_evaluators()
    findings = []
    for rule in RULES:
        evidence_items = EVALUATORS[rule["evaluator"]](rule, inventory)
        if evidence_items:
            findings.append(finding(rule["id"], evidence_items))
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
            "host": (items(inventory, "host-platform") or {}).get("hostname", "unknown"),
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
        "assessment": assessment(findings, inventory),
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
