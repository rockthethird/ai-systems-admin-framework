"""Load the prevalidated audit policy manifest for reporting runtimes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MANIFEST_VERSION = "ai-auditor-policy-manifest/v1"
PUBLIC_FIELDS = ("title", "severity", "category", "rationale", "impact", "recommendation")


def manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / "policy" / "manifest.json"


def load_manifest() -> dict[str, Any]:
    manifest = json.loads(manifest_path().read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise ValueError("unsupported audit policy manifest")
    return manifest


def rule_catalog(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = manifest.get("rules", {}).get("rules")
    if not isinstance(rules, list):
        raise ValueError("audit policy rule catalog is invalid")
    catalog = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or rule["id"] in catalog:
            raise ValueError("audit policy contains an invalid or duplicate rule")
        if any(not isinstance(rule.get(field), str) or not rule[field] for field in PUBLIC_FIELDS):
            raise ValueError(f"audit policy rule {rule['id']} has invalid public text")
        catalog[rule["id"]] = rule
    return catalog


def profile_catalog(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = manifest.get("profiles", {}).get("profiles")
    if not isinstance(profiles, list):
        raise ValueError("audit policy profile catalog is invalid")
    catalog = {profile["id"]: profile for profile in profiles if isinstance(profile, dict) and "id" in profile}
    if len(catalog) != len(profiles):
        raise ValueError("audit policy contains an invalid or duplicate profile")
    return catalog


MANIFEST = load_manifest()
RULES = rule_catalog(MANIFEST)
PROFILES = profile_catalog(MANIFEST)
