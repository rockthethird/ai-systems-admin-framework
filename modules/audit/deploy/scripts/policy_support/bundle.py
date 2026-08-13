"""Validate audit policy and construct its deterministic deployment bundle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import types
from pathlib import Path
from typing import Any

import jsonschema
import yaml

MANIFEST_VERSION = "ai-auditor-policy-manifest/v1"
INDEX_VERSION = "ai-auditor-artifact-index/v1"
POLICY_FILES = {
    "collectors": ("collectors.yaml", "collectors-v1.schema.json"),
    "deployment": ("deployment.yaml", "deployment-v1.schema.json"),
    "identities": ("identities.yaml", "identities-v1.schema.json"),
    "profiles": ("profiles.yaml", "profiles-v1.schema.json"),
    "rules": ("rules.yaml", "rules-v1.schema.json"),
}
EXTERNAL_REQUIRED_EXCLUSIONS = {
    "raw-inventory", "host-identity", "collection-timestamps",
    "evidence-paths", "evidence-values", "raw-errors",
}
def fail(message: str) -> None:
    raise ValueError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=4, sort_keys=True) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def regular_file_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"required artifact is not a regular file: {path}")
    return path.read_bytes()


def unique(items: list[dict[str, Any]], field: str, label: str) -> set[str]:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        fail(f"duplicate {label} {field}")
    return set(values)


def load_policy(policy_dir: Path) -> tuple[dict[str, Any], str]:
    expected = {policy_file for policy_file, _ in POLICY_FILES.values()}
    actual = {path.name for path in policy_dir.glob("*.yaml")}
    if actual != expected:
        fail(f"policy files do not match explicit list; "
             f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")

    documents: dict[str, Any] = {}
    source_files = []
    schema_dir = policy_dir / "schema"
    for kind, (policy_name, schema_name) in POLICY_FILES.items():
        raw = (policy_dir / policy_name).read_bytes()
        document = yaml.safe_load(raw)
        schema = json.loads((schema_dir / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(document)
        documents[kind] = document
        source_files.append({"path": policy_name, "sha256": sha256(raw)})

    policy_source = {"files": sorted(source_files, key=lambda item: item["path"])}
    return documents, sha256(canonical_json(policy_source))


def load_source_module(module_dir: Path, relative: str, name: str) -> types.ModuleType:
    """Execute one explicit, regular repository source file as a private module."""
    source = module_dir.joinpath(*Path(relative).parts)
    content = source_bytes(module_dir, relative)
    module = types.ModuleType(name)
    module.__file__ = str(source)
    exec(compile(content, str(source), "exec"), module.__dict__)
    return module


def validate_policy(documents: dict[str, Any], module_dir: Path) -> None:
    collector_policy = load_source_module(
        module_dir, "runtime/collect/collector_policy.py", "_ai_auditor_collector_policy")
    collector_policy.validate_collector_policy(documents["collectors"])

    collectors = documents["collectors"]["collectors"]
    rules = documents["rules"]["rules"]
    profiles = documents["profiles"]["profiles"]
    identities = documents["identities"]["identities"]
    deployment = documents["deployment"]

    collector_ids = unique(collectors, "id", "collector")
    unique(rules, "id", "rule")
    unique(rules, "control", "rule")
    profile_ids = unique(profiles, "id", "profile")
    unique(identities, "user", "identity")
    unique(identities, "endpoint", "identity")
    unique(deployment["files"], "id", "deployment file")
    file_destinations = unique(deployment["files"], "destination", "deployment file")
    directory_destinations = unique(
        deployment["directories"], "destination", "deployment directory")
    if file_destinations & directory_destinations:
        fail("deployment destination cannot be both a file and directory")

    generated = [item["generated"] for item in deployment["files"] if "generated" in item]
    if sorted(generated) != ["policy-manifest", "sudoers"]:
        fail("deployment must contain exactly one policy-manifest and sudoers generator")
    for item in deployment["files"]:
        destination = item["destination"]
        if (destination.startswith("/opt/ai-auditor/")
                and str(Path(destination).parent) not in directory_destinations):
            fail(f"deployment file parent is not declared: {destination}")
    executable_destinations = {item["destination"] for item in deployment["files"]
                               if item["mode"] == "0755"}
    if {identity["endpoint"] for identity in identities} - executable_destinations:
        fail("identity endpoint is not a declared executable deployment file")

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


def compile_manifest(documents: dict[str, Any]) -> bytes:
    return canonical_json({
        "version": MANIFEST_VERSION,
        "collectors": documents["collectors"],
        "rules": documents["rules"],
        "profiles": documents["profiles"],
        "identities": documents["identities"],
    })


def render_sudoers(documents: dict[str, Any]) -> bytes:
    identities = sorted(documents["identities"]["identities"], key=lambda item: item["user"])
    lines = [
        "# Generated by ai-auditor policy.py - DO NOT EDIT DIRECTLY",
        "# Modify deploy/policy/identities.yaml and rebuild instead.",
        "",
    ]
    for identity in identities:
        lines.append(f"{identity['user']} ALL=(root:root) NOPASSWD: {identity['endpoint']} \"\"")

    lines.extend(["", "# Environment hardening"])
    for identity in identities:
        user = identity["user"]
        lines.extend([
            f"Defaults:{user} env_reset",
            f'Defaults:{user} secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"',
            f'Defaults:{user} env_delete="LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PATH_ORIG LD_AUDIT LD_DEBUG"',
            f'Defaults:{user} env_keep="LANGUAGE LANG LC_*"',
            f'Defaults:{user} logfile="/var/log/sudo-{user}.log"',
            f"Defaults:{user} !requiretty",
        ])
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_staged(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)


def validate_sudoers(path: Path) -> None:
    visudo = shutil.which("visudo")
    if visudo is None:
        fail("visudo is required to build deployment artifacts")
    result = subprocess.run(
        [visudo, "-c", "-f", str(path)], check=False,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    if result.returncode:
        fail(f"generated sudoers failed validation:\n{result.stdout.rstrip()}")


def validate_runtime(entries: list[dict[str, str]], contents: dict[str, bytes],
                     validation_dir: Path) -> None:
    for entry in entries:
        if entry["kind"] != "file":
            continue
        destination = entry["destination"]
        content = contents[entry["bundle_path"]]
        if destination.endswith(".py"):
            compile(content, destination, "exec")
        elif destination.startswith("/opt/ai-auditor/bin/"):
            candidate = validation_dir / entry["id"]
            write_staged(candidate, content, 0o700)
            if subprocess.run(["/usr/bin/bash", "-n", str(candidate)], check=False).returncode:
                fail(f"runtime shell syntax is invalid: {destination}")


def source_bytes(module_dir: Path, relative: str) -> bytes:
    source = module_dir.joinpath(*Path(relative).parts)
    current = module_dir
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            fail(f"deployment source cannot be a symlink: {relative}")
    resolved_module = module_dir.resolve(strict=True)
    resolved_source = source.resolve(strict=True)
    if resolved_source.parent != resolved_module and resolved_module not in resolved_source.parents:
        fail(f"deployment source escapes the audit module: {relative}")
    if not resolved_source.is_file():
        fail(f"deployment source is not a regular file: {relative}")
    return resolved_source.read_bytes()


def bundle_path(destination: str) -> str:
    return "rootfs" + destination


def resolve_bundle(documents: dict[str, Any], module_dir: Path
                   ) -> tuple[list[dict[str, str]], dict[str, bytes]]:
    generated = {
        "policy-manifest": compile_manifest(documents),
        "sudoers": render_sudoers(documents),
    }
    entries = []
    contents = {}
    for directory in documents["deployment"]["directories"]:
        entries.append({"kind": "directory", "bundle_path": bundle_path(directory["destination"]),
                        **directory})
    for item in documents["deployment"]["files"]:
        content = (source_bytes(module_dir, item["source"])
                   if "source" in item else generated[item["generated"]])
        path = bundle_path(item["destination"])
        metadata = {field: item[field]
                    for field in ("id", "destination", "owner", "group", "mode")}
        origin = ({"source": item["source"]} if "source" in item
                  else {"generated": item["generated"]})
        entries.append({"kind": "file", "bundle_path": path,
                        "sha256": sha256(content), **origin, **metadata})
        contents[path] = content
    entries.sort(key=lambda item: (item["destination"], item["kind"]))
    return entries, contents


def build_index(policy_sha256: str, entries: list[dict[str, str]]) -> bytes:
    return canonical_json({
        "schema_version": INDEX_VERSION,
        "policy_sha256": policy_sha256,
        "entries": entries,
    })


def render_bundle(policy_dir: Path, module_dir: Path, validation_dir: Path
                  ) -> tuple[list[dict[str, str]], dict[str, bytes], bytes, str]:
    documents, policy_digest = load_policy(policy_dir)
    validate_policy(documents, module_dir)
    entries, contents = resolve_bundle(documents, module_dir)
    validate_runtime(entries, contents, validation_dir)
    sudoers_entry = next(item for item in entries if item.get("id") == "sudoers")
    sudoers = validation_dir / "sudoers"
    write_staged(sudoers, contents[sudoers_entry["bundle_path"]], 0o644)
    validate_sudoers(sudoers)
    return entries, contents, build_index(policy_digest, entries), policy_digest


def stage_bundle(stage_dir: Path, entries: list[dict[str, str]],
                 contents: dict[str, bytes], index: bytes) -> None:
    for entry in entries:
        path = stage_dir / entry["bundle_path"]
        mode = int(entry["mode"], 8)
        if entry["kind"] == "directory":
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        else:
            write_staged(path, contents[entry["bundle_path"]], mode)
    for structural in (stage_dir / "rootfs", stage_dir / "rootfs/opt",
                       stage_dir / "rootfs/etc", stage_dir / "rootfs/etc/sudoers.d"):
        structural.chmod(0o755)
    write_staged(stage_dir / "artifact-index.json", index, 0o644)


def activate_build(stage_dir: Path, artifacts_dir: Path) -> None:
    rootfs = artifacts_dir / "rootfs"
    backup = artifacts_dir / ".rootfs-previous"
    if backup.exists():
        shutil.rmtree(backup)
    if rootfs.exists():
        os.replace(rootfs, backup)
    try:
        os.replace(stage_dir / "rootfs", rootfs)
        os.replace(stage_dir / "artifact-index.json", artifacts_dir / "artifact-index.json")
    except BaseException:
        if not rootfs.exists() and backup.exists():
            os.replace(backup, rootfs)
        raise
    if backup.exists():
        shutil.rmtree(backup)


def build(policy_dir: Path, module_dir: Path, artifacts_dir: Path) -> tuple[str, str]:
    artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    artifacts_dir.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=artifacts_dir) as temporary:
        stage_dir = Path(temporary)
        entries, contents, index, policy_digest = render_bundle(
            policy_dir, module_dir, stage_dir)
        stage_bundle(stage_dir, entries, contents, index)
        activate_build(stage_dir, artifacts_dir)
    return policy_digest, sha256(index)


def expected_bundle(policy_dir: Path, module_dir: Path
                    ) -> tuple[list[dict[str, str]], dict[str, bytes], bytes, str]:
    with tempfile.TemporaryDirectory(prefix="ai-auditor-verify-") as temporary:
        return render_bundle(policy_dir, module_dir, Path(temporary))
