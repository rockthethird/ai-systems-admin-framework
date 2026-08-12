#!/usr/bin/python3
"""Build deterministic deployment artifacts from declarative audit policy."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema
import yaml

MANIFEST_VERSION = "ai-auditor-policy-manifest/v1"
INDEX_VERSION = "ai-auditor-artifact-index/v1"
APPROVAL_FILE = "policy-approval.json"
POLICY_FILES = {
    "collectors": ("collectors.yaml", "collectors-v1.schema.json"),
    "identities": ("identities.yaml", "identities-v1.schema.json"),
    "profiles": ("profiles.yaml", "profiles-v1.schema.json"),
    "rules": ("rules.yaml", "rules-v1.schema.json"),
}
ARTIFACTS = {
    "policy-manifest.json": {
        "destination": "/usr/local/libexec/ai-auditor-policy-manifest.json",
        "owner": "root",
        "group": "root",
        "mode": "0600",
    },
    "sudoers-ai-auditor": {
        "destination": "/etc/sudoers.d/ai-auditor",
        "owner": "root",
        "group": "root",
        "mode": "0440",
    },
}
EXTERNAL_REQUIRED_EXCLUSIONS = {
    "raw-inventory", "host-identity", "collection-timestamps",
    "evidence-paths", "evidence-values", "raw-errors",
}
BUILTIN_PARAMETERS = {
    "passwd-entries": set(),
    "ssh-effective-settings": {"users", "settings", "executable_paths"},
    "account-path-metadata": {"users", "relative_paths"},
    "path-metadata": {"paths"},
}


def fail(message: str) -> None:
    raise ValueError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=4, sort_keys=True) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def unique(items: list[dict[str, Any]], field: str, label: str) -> set[str]:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        fail(f"duplicate {label} {field}")
    return set(values)


def load_policy(policy_dir: Path) -> tuple[dict[str, Any], str]:
    expected = {policy_file for policy_file, _ in POLICY_FILES.values()}
    actual = {path.name for path in policy_dir.glob("*.yaml")}
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        fail(f"policy files do not match explicit list; missing={missing}, unexpected={unexpected}")

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


def validate_policy(documents: dict[str, Any]) -> None:
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
                if any(token in argument for argument in command["args"]
                       for token in ("$(", "`", "${", "{{", "}}")):
                    fail(f"collector {collector['id']} contains interpolation or template syntax")
                output_mode = command.get("output_mode")
                if output_mode == "dpkg-package-lines" and not (
                        command["path"] == "/usr/bin/dpkg-query" and command["args"] == ["-W"]):
                    fail("dpkg-package-lines is valid only for the fixed dpkg-query command")
                if output_mode == "docker-json-lines" and not (
                        command["path"] in {"/usr/bin/docker", "/usr/local/bin/docker"}
                        and command["args"] == ["ps", "--all", "--no-trunc"]):
                    fail("docker-json-lines is valid only for the fixed docker ps command")
        else:
            expected = BUILTIN_PARAMETERS[collector["primitive"]]
            actual = set(collector.get("parameters", {}))
            if actual != expected:
                fail(f"collector {collector['id']} parameters do not match {collector['primitive']}")
            for value in collector.get("parameters", {}).get("paths", []):
                if not value.startswith("/"):
                    fail(f"collector {collector['id']} path is not absolute")
            for value in collector.get("parameters", {}).get("executable_paths", []):
                if not value.startswith("/"):
                    fail(f"collector {collector['id']} executable path is not absolute")

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
        lines.append(
            f"{identity['user']} ALL=(root:root) NOPASSWD: {identity['endpoint']} \"\""
        )

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


def validate_sudoers(path: Path) -> None:
    visudo = shutil.which("visudo")
    if visudo is None:
        fail("visudo is required to build deployment artifacts")
    result = subprocess.run(
        [visudo, "-c", "-f", str(path)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode:
        fail(f"generated sudoers failed validation:\n{result.stdout.rstrip()}")


def build_index(policy_sha256: str, contents: dict[str, bytes]) -> bytes:
    artifacts = []
    for name, metadata in ARTIFACTS.items():
        artifacts.append({"file": name, "sha256": sha256(contents[name]), **metadata})
    artifacts.sort(key=lambda item: item["destination"])
    return canonical_json({
        "schema_version": INDEX_VERSION,
        "policy_sha256": policy_sha256,
        "artifacts": artifacts,
    })


def render_bundle(policy_dir: Path, validation_dir: Path) -> tuple[dict[str, bytes], bytes, str]:
    documents, policy_digest = load_policy(policy_dir)
    validate_policy(documents)
    contents = {
        "policy-manifest.json": compile_manifest(documents),
        "sudoers-ai-auditor": render_sudoers(documents),
    }
    sudoers = validation_dir / "sudoers-ai-auditor"
    write_staged(sudoers, contents["sudoers-ai-auditor"])
    validate_sudoers(sudoers)
    return contents, build_index(policy_digest, contents), policy_digest


def write_staged(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o644)


def build(policy_dir: Path, artifacts_dir: Path) -> tuple[str, str]:
    artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
    artifacts_dir.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=artifacts_dir) as temporary:
        stage_dir = Path(temporary)
        contents, index, policy_digest = render_bundle(policy_dir, stage_dir)
        for name, content in contents.items():
            write_staged(stage_dir / name, content)
        write_staged(stage_dir / "artifact-index.json", index)
        for name in ARTIFACTS:
            os.replace(stage_dir / name, artifacts_dir / name)
        os.replace(stage_dir / "artifact-index.json", artifacts_dir / "artifact-index.json")

    return policy_digest, sha256(index)


def expected_bundle(policy_dir: Path) -> tuple[dict[str, bytes], bytes, str]:
    with tempfile.TemporaryDirectory(prefix="ai-auditor-verify-") as temporary:
        return render_bundle(policy_dir, Path(temporary))


def regular_file_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        fail(f"required artifact is not a regular file: {path}")
    return path.read_bytes()


def approval_path(state_dir: Path) -> Path:
    return state_dir / APPROVAL_FILE


def validate_approval_storage(policy_dir: Path, state_dir: Path) -> None:
    policy_owner = policy_dir.stat().st_uid
    if state_dir.is_symlink() or not state_dir.is_dir():
        fail(f"approval state directory is missing or invalid: {state_dir}")
    state = state_dir.stat()
    if state.st_uid != policy_owner or stat.S_IMODE(state.st_mode) != 0o700:
        fail(f"approval state directory must be owned by policy owner with mode 0700: {state_dir}")
    record_path = approval_path(state_dir)
    record = record_path.stat()
    if record.st_uid != policy_owner or stat.S_IMODE(record.st_mode) != 0o600:
        fail(f"approval record must be owned by policy owner with mode 0600: {record_path}")


def verify(policy_dir: Path, artifacts_dir: Path, state_dir: Path) -> tuple[str, str]:
    contents, index, policy_digest = expected_bundle(policy_dir)
    for name, expected in contents.items():
        if regular_file_bytes(artifacts_dir / name) != expected:
            fail(f"artifact does not match validated policy: {artifacts_dir / name}")
    if regular_file_bytes(artifacts_dir / "artifact-index.json") != index:
        fail("artifact index does not match the reconstructed bundle")

    validate_approval_storage(policy_dir, state_dir)
    approval = json.loads(regular_file_bytes(approval_path(state_dir)))
    if not isinstance(approval, dict):
        fail("approval record must be a JSON object")
    bundle_digest = sha256(index)
    expected_approval = {
        "policy_sha256": policy_digest,
        "bundle_sha256": bundle_digest,
    }
    for field, expected in expected_approval.items():
        if approval.get(field) != expected:
            fail(f"approval {field} does not match the current bundle")
    if not isinstance(approval.get("approved_at"), str) or not approval["approved_at"]:
        fail("approval record has no valid approved_at value")
    if not isinstance(approval.get("approved_by"), str) or not approval["approved_by"]:
        fail("approval record has no valid approved_by value")
    if set(approval) != {"policy_sha256", "bundle_sha256", "approved_at", "approved_by"}:
        fail("approval record contains unexpected fields")
    try:
        datetime.datetime.strptime(approval["approved_at"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail("approval timestamp is not UTC RFC 3339 with whole-second precision")
    expected_approver = pwd.getpwuid(policy_dir.stat().st_uid).pw_name
    if approval["approved_by"] != expected_approver:
        fail("approval identity does not match the policy-directory owner")
    return policy_digest, bundle_digest


def print_review(artifacts_dir: Path, index: bytes, bundle_digest: str) -> None:
    metadata = {item["file"]: item for item in json.loads(index)["artifacts"]}
    for name in sorted(ARTIFACTS, key=lambda item: metadata[item]["destination"]):
        item = metadata[name]
        print("=" * 78)
        print(f"ARTIFACT: {name}")
        print(f"DESTINATION: {item['destination']}")
        print(f"OWNER: {item['owner']}:{item['group']}")
        print(f"MODE: {item['mode']}")
        print(f"SHA256: {item['sha256']}")
        print("----- EXACT CONTENT BEGINS -----")
        sys.stdout.write(regular_file_bytes(artifacts_dir / name).decode("utf-8"))
        print("----- EXACT CONTENT ENDS -----")
    print("=" * 78)
    print("ARTIFACT INDEX (exact approved bytes)")
    print("----- EXACT CONTENT BEGINS -----")
    sys.stdout.write(index.decode("utf-8"))
    print("----- EXACT CONTENT ENDS -----")
    print(f"BUNDLE SHA256: {bundle_digest}")


def write_approval(policy_dir: Path, state_dir: Path, policy_digest: str,
                   bundle_digest: str) -> None:
    policy_owner = policy_dir.stat().st_uid
    if os.geteuid() != policy_owner:
        fail("review must run as the account that owns the policy directory")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if state_dir.is_symlink() or not state_dir.is_dir():
        fail(f"approval state path is not a directory: {state_dir}")
    if state_dir.stat().st_uid != policy_owner:
        fail("approval state directory is not owned by the policy owner")
    state_dir.chmod(0o700)

    approved_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    record = canonical_json({
        "policy_sha256": policy_digest,
        "bundle_sha256": bundle_digest,
        "approved_at": approved_at.isoformat().replace("+00:00", "Z"),
        "approved_by": pwd.getpwuid(os.geteuid()).pw_name,
    })
    descriptor, temporary = tempfile.mkstemp(prefix=".approval-", dir=state_dir)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(record)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, approval_path(state_dir))
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def review(policy_dir: Path, artifacts_dir: Path, state_dir: Path) -> tuple[str, str]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        fail("review requires an interactive terminal on stdin and stdout")
    if os.geteuid() != policy_dir.stat().st_uid:
        fail("review must run as the account that owns the policy directory")

    policy_digest, bundle_digest = build(policy_dir, artifacts_dir)
    contents, index, expected_policy_digest = expected_bundle(policy_dir)
    if policy_digest != expected_policy_digest:
        fail("policy changed while preparing review")
    for name, expected in contents.items():
        if regular_file_bytes(artifacts_dir / name) != expected:
            fail(f"artifact changed while preparing review: {name}")
    if regular_file_bytes(artifacts_dir / "artifact-index.json") != index:
        fail("artifact index changed while preparing review")

    print_review(artifacts_dir, index, bundle_digest)
    entered = input("Type the complete bundle SHA-256 to approve: ").strip()
    if entered != bundle_digest:
        fail("bundle digest did not match; approval was not created")
    write_approval(policy_dir, state_dir, policy_digest, bundle_digest)
    return policy_digest, bundle_digest


def parse_args() -> argparse.Namespace:
    deploy_dir = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    def paths(command: argparse.ArgumentParser, include_state: bool = False) -> None:
        command.add_argument("--policy-dir", type=Path, default=deploy_dir / "policy")
        command.add_argument("--artifacts-dir", type=Path, default=deploy_dir / "artifacts")
        if include_state:
            command.add_argument("--state-dir", type=Path, default=deploy_dir / ".state")

    build_parser = commands.add_parser("build", help="build and validate deployment artifacts")
    paths(build_parser)
    verify_parser = commands.add_parser("verify", help="verify the bundle and its approval")
    paths(verify_parser, include_state=True)
    review_parser = commands.add_parser("review", help="review and approve exact artifact bytes")
    paths(review_parser, include_state=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "build":
            policy_digest, bundle_digest = build(args.policy_dir, args.artifacts_dir)
            print(f"policy_sha256: {policy_digest}")
            print(f"bundle_sha256: {bundle_digest}")
            print("approval_status: UNAPPROVED")
        elif args.command == "verify":
            policy_digest, bundle_digest = verify(args.policy_dir, args.artifacts_dir, args.state_dir)
            print(f"policy_sha256: {policy_digest}")
            print(f"bundle_sha256: {bundle_digest}")
            print("approval_status: APPROVED")
        elif args.command == "review":
            policy_digest, bundle_digest = review(args.policy_dir, args.artifacts_dir, args.state_dir)
            print(f"policy_sha256: {policy_digest}")
            print(f"bundle_sha256: {bundle_digest}")
            print("approval_status: APPROVED")
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError,
            jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        print(f"policy command failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
