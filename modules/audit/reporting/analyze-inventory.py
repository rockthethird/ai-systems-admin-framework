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
RULES = (
    ("AIA-1001", "filesystem-utilization", "filesystems", "Filesystem utilization remains below 90%"),
    ("AIA-1002", "systemd-failed-units", "systemd.failed_units", "Systemd reports no failed units"),
    ("AIA-1003", "additional-uid-zero-accounts", "accounts", "No additional UID 0 accounts were found"),
    ("AIA-1004", "inventory-completeness", "collection", "Required inventory collection completed"),
    ("AIA-1101", "ssh-password-authentication", "security.ssh", "SSH password authentication is disabled for auditor identities"),
    ("AIA-1102", "ssh-root-login", "security.ssh", "Direct SSH root login is disabled"),
    ("AIA-1103", "auditor-interactive-shell", "security.auditor_accounts", "Auditor identities use non-interactive shells"),
    ("AIA-1104", "report-endpoint-integrity", "security.report_endpoints", "Report endpoints are owned by root and not writable by other users"),
    ("AIA-1105", "auditor-path-permissions", "security.auditor_accounts", "Auditor homes and authorized_keys have restrictive ownership and modes"),
)


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


def ssh_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    users = inventory.get("security", {}).get("ssh", {}).get("users", [])
    password = []
    root_login = []
    for index, user in enumerate(users if isinstance(users, list) else []):
        settings = user.get("settings", {}) if isinstance(user, dict) else {}
        name = user.get("name", "unknown") if isinstance(user, dict) else "unknown"
        if settings.get("passwordauthentication") != "no" or settings.get("kbdinteractiveauthentication") != "no":
            password.append(evidence("security.ssh", f"/security/ssh/users/{index}/settings",
                                     f"password-capable SSH authentication is enabled for {name}"))
        if settings.get("permitrootlogin") != "no":
            root_login.append(evidence("security.ssh", f"/security/ssh/users/{index}/settings/permitrootlogin",
                                       f"PermitRootLogin is {settings.get('permitrootlogin', 'unknown')}"))
    findings = []
    if password:
        findings.append(finding("AIA-1101", "SSH permits password-capable authentication", "high", "access-control", password,
                                "Password-capable SSH authentication expands the remote credential attack surface.",
                                "Guessed, reused, or disclosed passwords may permit remote access.",
                                "Disable password and keyboard-interactive authentication for auditor identities after validating key access.", 0.99))
    if root_login:
        findings.append(finding("AIA-1102", "SSH permits direct root login", "medium", "access-control", root_login,
                                "Direct root SSH authentication bypasses attribution through a named administrative account.",
                                "A compromised root credential provides immediate unrestricted host authority.",
                                "Set PermitRootLogin to no after validating an alternate administrative recovery path.", 0.98))
    return findings


def auditor_account_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    accounts = inventory.get("security", {}).get("auditor_accounts", [])
    shells = []
    paths = []
    for index, account in enumerate(accounts if isinstance(accounts, list) else []):
        if not isinstance(account, dict):
            continue
        if not account.get("exists"):
            paths.append(evidence("security.auditor_accounts", f"/security/auditor_accounts/{index}",
                                  f"auditor account {account.get('name', 'unknown')} is missing"))
            continue
        if account.get("shell") not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}:
            shells.append(evidence("security.auditor_accounts", f"/security/auditor_accounts/{index}/shell",
                                   f"auditor account {account.get('name', 'unknown')} uses an interactive shell"))
        expected_uid = account.get("uid")
        home = account.get("home_metadata") or {}
        authorized = account.get("authorized_keys_metadata") or {}
        try:
            home_mode = int(str(home.get("mode")), 8)
        except (TypeError, ValueError):
            home_mode = -1
        if not home.get("exists") or home.get("uid") != expected_uid or home_mode < 0 or home_mode & 0o022:
            paths.append(evidence("security.auditor_accounts", f"/security/auditor_accounts/{index}/home_metadata",
                                  f"auditor account {account.get('name', 'unknown')} home ownership or mode is unsafe"))
        if authorized.get("exists"):
            try:
                key_mode = int(str(authorized.get("mode")), 8)
            except (TypeError, ValueError):
                key_mode = -1
            if authorized.get("uid") != expected_uid or key_mode < 0 or key_mode & 0o077:
                paths.append(evidence("security.auditor_accounts", f"/security/auditor_accounts/{index}/authorized_keys_metadata",
                                      f"auditor account {account.get('name', 'unknown')} authorized_keys ownership or mode is unsafe"))
    findings = []
    if shells:
        findings.append(finding("AIA-1103", "Auditor identities have interactive shells", "medium", "access-control", shells,
                                "An interactive shell increases the impact of an SSH command-boundary failure.",
                                "A compromised auditor credential may gain a general-purpose command environment.",
                                "Use a non-interactive shell together with an SSH forced command for report-only identities.", 0.99))
    if paths:
        findings.append(finding("AIA-1105", "Auditor account paths have unsafe permissions", "high", "file-integrity", paths,
                                "Writable account homes or key files can let another identity alter SSH authentication behavior.",
                                "An attacker may replace trusted keys or influence the report identity's login environment.",
                                "Restore account ownership and remove group or other write access; restrict authorized_keys to its owner.", 0.98))
    return findings


def endpoint_findings(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints = inventory.get("security", {}).get("report_endpoints", [])
    unsafe = []
    for index, endpoint in enumerate(endpoints if isinstance(endpoints, list) else []):
        if not isinstance(endpoint, dict):
            continue
        try:
            mode = int(str(endpoint.get("mode")), 8)
        except (TypeError, ValueError):
            mode = -1
        if not endpoint.get("exists") or endpoint.get("uid") != 0 or endpoint.get("gid") != 0 or mode < 0 or mode & 0o022:
            unsafe.append(evidence("security.report_endpoints", f"/security/report_endpoints/{index}",
                                   "a report endpoint is missing, not root-owned, or writable by non-root"))
    if not unsafe:
        return []
    return [finding("AIA-1104", "Report endpoint integrity is not enforced", "critical", "privilege-boundary", unsafe,
                    "The sudo boundary trusts fixed report endpoint files executed as root.",
                    "Modification of an endpoint can turn the narrow sudo capability into arbitrary root execution.",
                    "Install every endpoint as root-owned and remove group and other write permissions.", 0.99)]


def result_available(value: Any) -> bool:
    return (isinstance(value, dict) and value.get("available") is True
            and value.get("truncated") is False and not value.get("error"))


def assessment(findings: list[dict[str, Any]], inventory: dict[str, Any]) -> dict[str, Any]:
    failed = {item["id"] for item in findings}
    availability = {
        "AIA-1001": result_available(inventory.get("filesystems")),
        "AIA-1002": result_available(inventory.get("systemd", {}).get("failed_units")),
        "AIA-1003": isinstance(inventory.get("accounts"), list),
        # This rule evaluates the completeness of every required command result,
        # so its own evidence is always sufficient when the inventory is valid.
        "AIA-1004": True,
        "AIA-1101": inventory.get("security", {}).get("ssh", {}).get("available") is True,
        "AIA-1102": inventory.get("security", {}).get("ssh", {}).get("available") is True,
        "AIA-1103": isinstance(inventory.get("security", {}).get("auditor_accounts"), list),
        "AIA-1104": isinstance(inventory.get("security", {}).get("report_endpoints"), list),
        "AIA-1105": isinstance(inventory.get("security", {}).get("auditor_accounts"), list),
    }
    results = []
    for identifier, control, section, passed_summary in RULES:
        status = "failed" if identifier in failed else ("passed" if availability[identifier] else "unknown")
        results.append({"id": identifier, "control": control, "section": section,
                        "status": status, "summary": passed_summary if status == "passed" else None})
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("passed", "failed", "unknown")}
    return {"rules_evaluated": len(results), **counts, "results": results}


def analyze(raw_inventory: bytes) -> dict[str, Any]:
    inventory = json.loads(raw_inventory)
    if inventory.get("schema_version") != "1.0":
        raise ValueError("unsupported inventory schema_version")
    findings = []
    for rule in (filesystem_findings, failed_unit_findings, account_findings, collection_findings,
                 ssh_findings, auditor_account_findings, endpoint_findings):
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
