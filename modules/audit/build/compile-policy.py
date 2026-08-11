#!/usr/bin/python3
"""Validate declarative audit policy and compile a deterministic JSON manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml

MANIFEST_VERSION = "ai-auditor-policy-manifest/v1"
POLICY_FILES = {
    "collectors": ("collectors.yaml", "collectors-v1.schema.json"),
    "rules": ("rules.yaml", "rules-v1.schema.json"),
    "profiles": ("profiles.yaml", "profiles-v1.schema.json"),
    "identities": ("identities.yaml", "identities-v1.schema.json"),
}
EXTERNAL_REQUIRED_EXCLUSIONS = {
    "raw-inventory", "host-identity", "collection-timestamps",
    "evidence-paths", "evidence-values", "raw-errors",
}
BUILTIN_PARAMETERS = {
    "passwd-entries": set(),
    "ssh-effective-settings": {"users", "settings"},
    "account-path-metadata": {"users", "relative_paths"},
    "path-metadata": {"paths"},
}


def fail(message: str) -> None:
    raise ValueError(message)


def unique(items: list[dict[str, Any]], field: str, label: str) -> set[str]:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        fail(f"duplicate {label} {field}")
    return set(values)


def load(policy_dir: Path, schema_dir: Path) -> tuple[dict[str, Any], dict[str, str]]:
    documents = {}
    digests = {}
    for name, (policy_name, schema_name) in POLICY_FILES.items():
        policy_path = policy_dir / policy_name
        raw = policy_path.read_bytes()
        document = yaml.safe_load(raw)
        schema = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(document)
        documents[name] = document
        digests[policy_name] = hashlib.sha256(raw).hexdigest()
    return documents, digests


def validate(documents: dict[str, Any]) -> None:
    collectors = documents["collectors"]["collectors"]
    rules = documents["rules"]["rules"]
    profiles = documents["profiles"]["profiles"]
    identities = documents["identities"]["identities"]

    collector_ids = unique(collectors, "id", "collector")
    unique(rules, "id", "rule")
    unique(rules, "control", "rule")
    profile_ids = unique(profiles, "id", "profile")
    unique(identities, "user", "identity")
    unique(identities, "endpoint", "identity")

    for collector in collectors:
        if collector["type"] == "command":
            for command in collector["candidates"]:
                if not command["path"].startswith("/"):
                    fail(f"collector {collector['id']} command is not absolute")
                if any("\x00" in argument for argument in command["args"]):
                    fail(f"collector {collector['id']} contains a NUL argument")
        else:
            expected = BUILTIN_PARAMETERS[collector["primitive"]]
            actual = set(collector.get("parameters", {}))
            if actual != expected:
                fail(f"collector {collector['id']} parameters do not match {collector['primitive']}")
            for value in collector.get("parameters", {}).get("paths", []):
                if not value.startswith("/"):
                    fail(f"collector {collector['id']} path is not absolute")

    for rule in rules:
        if rule["source"] != "all-required-collectors" and rule["source"] not in collector_ids:
            fail(f"rule {rule['id']} references unknown collector {rule['source']}")

    for profile in profiles:
        overlap = set(profile["include"]) & set(profile["exclude"])
        if overlap:
            fail(f"profile {profile['id']} both includes and excludes {sorted(overlap)}")
        if profile["id"] == "external-safe/v1":
            missing = EXTERNAL_REQUIRED_EXCLUSIONS - set(profile["exclude"])
            if missing or profile["evidence"] != "count-and-section":
                fail(f"external-safe profile weakens required disclosure exclusions: {sorted(missing)}")

    if {identity["profile"] for identity in identities} != profile_ids:
        fail("every profile must be bound to exactly one declared identity")


def compile_manifest(policy_dir: Path) -> dict[str, Any]:
    schema_dir = policy_dir / "schema"
    documents, digests = load(policy_dir, schema_dir)
    validate(documents)
    return {
        "version": MANIFEST_VERSION,
        "source_sha256": dict(sorted(digests.items())),
        "collectors": documents["collectors"],
        "rules": documents["rules"],
        "profiles": documents["profiles"],
        "identities": documents["identities"],
    }


def main() -> int:
    default_policy = Path(__file__).resolve().parent.parent / "policy"
    default_output = Path(__file__).resolve().parent.parent / "generated" / "policy-manifest.json"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-dir", type=Path, default=default_policy)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument("--check", action="store_true", help="fail if output differs; do not write")
    args = parser.parse_args()
    try:
        rendered = json.dumps(compile_manifest(args.policy_dir), indent=2, sort_keys=True) + "\n"
        if args.check:
            if not args.output.exists() or args.output.read_text(encoding="utf-8") != rendered:
                fail(f"generated policy manifest is stale: {args.output}")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError,
            jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        print(f"policy compilation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
