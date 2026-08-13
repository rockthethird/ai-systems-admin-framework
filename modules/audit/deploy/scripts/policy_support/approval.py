"""Verify, display, and record human approval of exact audit bundles."""

from __future__ import annotations

import datetime
import json
import os
import pwd
import stat
import sys
import tempfile
from pathlib import Path

from .bundle import (
    build,
    canonical_json,
    expected_bundle,
    fail,
    regular_file_bytes,
    sha256,
)

APPROVAL_FILE = "policy-approval.json"


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


def validate_approval(policy_dir: Path, state_dir: Path, policy_digest: str,
                      bundle_digest: str) -> None:
    validate_approval_storage(policy_dir, state_dir)
    approval = json.loads(regular_file_bytes(approval_path(state_dir)))
    if not isinstance(approval, dict):
        fail("approval record must be a JSON object")
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


def human_approval_status(policy_dir: Path, state_dir: Path, policy_digest: str,
                          bundle_digest: str) -> str:
    if not os.path.lexists(approval_path(state_dir)):
        return "REQUIRED"
    try:
        validate_approval(policy_dir, state_dir, policy_digest, bundle_digest)
    except (OSError, ValueError, json.JSONDecodeError):
        return "STALE"
    return "MATCHED"


def verify_tree(artifacts_dir: Path, entries: list[dict[str, str]],
                contents: dict[str, bytes]) -> None:
    rootfs = artifacts_dir / "rootfs"
    expected_paths = {entry["bundle_path"] for entry in entries}
    structural_paths = set()
    for expected in expected_paths:
        parent = Path(expected).parent
        while parent != Path("rootfs"):
            structural_paths.add(str(parent))
            parent = parent.parent
    actual_paths = ({str(path.relative_to(artifacts_dir)) for path in rootfs.rglob("*")}
                    if rootfs.is_dir() else set())
    allowed_paths = expected_paths | structural_paths
    if actual_paths != allowed_paths:
        fail(f"artifact rootfs does not match the deployment index; "
             f"missing={sorted(allowed_paths - actual_paths)}, "
             f"unexpected={sorted(actual_paths - allowed_paths)}")
    for relative in structural_paths:
        path = artifacts_dir / relative
        if path.is_symlink() or not path.is_dir():
            fail(f"artifact structural path is not a real directory: {path}")
    for entry in entries:
        path = artifacts_dir / entry["bundle_path"]
        if path.is_symlink():
            fail(f"artifact cannot be a symlink: {path}")
        if stat.S_IMODE(path.stat().st_mode) != int(entry["mode"], 8):
            fail(f"artifact has unexpected mode: {path}")
        if entry["kind"] == "directory":
            if not path.is_dir():
                fail(f"required artifact is not a directory: {path}")
        elif regular_file_bytes(path) != contents[entry["bundle_path"]]:
            fail(f"artifact does not match validated source: {path}")


def verify(policy_dir: Path, module_dir: Path, artifacts_dir: Path,
           state_dir: Path) -> tuple[str, str]:
    entries, contents, index, policy_digest = expected_bundle(policy_dir, module_dir)
    verify_tree(artifacts_dir, entries, contents)
    if regular_file_bytes(artifacts_dir / "artifact-index.json") != index:
        fail("artifact index does not match the reconstructed bundle")

    bundle_digest = sha256(index)
    status = human_approval_status(policy_dir, state_dir, policy_digest, bundle_digest)
    if status != "MATCHED":
        fail(f"human approval does not match the current bundle: {status}")
    return policy_digest, bundle_digest


def heading(title: str) -> None:
    print(title)
    print("-" * len(title))


def print_review(artifacts_dir: Path, index: bytes, policy_digest: str,
                 bundle_digest: str) -> None:
    entries = json.loads(index)["entries"]
    directories = [item for item in entries if item["kind"] == "directory"]
    files = [item for item in entries if item["kind"] == "file"]
    generated = [item for item in files if "generated" in item]
    copied = [item for item in files if "source" in item]

    print("AI AUDITOR DEPLOYMENT REVIEW")
    print("=" * 28)
    print()
    print("This report verifies bundle provenance and installation metadata.")
    print("It does not replace reviewing source changes or generated file contents.")
    print()
    print(f"Artifact root : {artifacts_dir}")
    print(f"Policy SHA-256: {policy_digest}")
    print(f"Bundle SHA-256: {bundle_digest}")
    print()

    heading("HOW TO REVIEW")
    print("1. Review copied source-code changes through Git.")
    print("2. Open and inspect every file in GENERATED CONTENT REQUIRING REVIEW.")
    print("3. Verify each file's origin, destination, ownership, mode, and bundle path.")
    print("4. Confirm that every file reports MATCHED provenance.")
    print("5. Approve only if this report's complete bundle digest is expected.")
    print()
    print("MATCHED confirms byte equality only. It does not mean that a human has")
    print("reviewed or approved the file's security.")
    print()

    heading("SUMMARY")
    print(f"Installation directories: {len(directories)}")
    print(f"Copied files          : {len(copied)}")
    print(f"Generated files       : {len(generated)}")
    print(f"Total files           : {len(files)}")
    print()

    heading("GENERATED CONTENT REQUIRING REVIEW")
    for item in generated:
        print(f"[ ] {item['id']}")
        print(f"    {artifacts_dir / item['bundle_path']}")
    print()
    print("Inspect every file above before approving the bundle.")
    print()

    heading("INSTALLATION DIRECTORIES")
    for item in directories:
        print(f"{item['destination']}")
        print(f"  Install as  : {item['owner']}:{item['group']} {item['mode']}")
        print(f"  Bundle path : {item['bundle_path']}")
    print()

    heading("FILES - INSTALLATION METADATA AND PROVENANCE")
    for number, item in enumerate(files, start=1):
        print(f"[{number}/{len(files)}] {item['id']}")
        print(f"  Destination : {item['destination']}")
        print(f"  Install as  : {item['owner']}:{item['group']} {item['mode']}")
        print(f"  Bundle path : {item['bundle_path']}")
        if "source" in item:
            print(f"  Source      : {item['source']}")
            provenance = "bundle bytes equal validated source"
        else:
            print(f"  Generator   : {item['generated']}")
            provenance = "bundle bytes equal deterministic generator output"
        print(f"  SHA-256     : {item['sha256']}")
        print(f"  Provenance  : MATCHED - {provenance}")
        print()

    heading("APPROVAL")
    print(f"Artifact index: {artifacts_dir / 'artifact-index.json'}")
    print(f"Policy SHA-256: {policy_digest}")
    print(f"Bundle SHA-256: {bundle_digest}")


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


def review(policy_dir: Path, module_dir: Path, artifacts_dir: Path,
           state_dir: Path) -> tuple[str, str]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        fail("review requires an interactive terminal on stdin and stdout")
    if os.geteuid() != policy_dir.stat().st_uid:
        fail("review must run as the account that owns the policy directory")

    policy_digest, bundle_digest = build(policy_dir, module_dir, artifacts_dir)
    entries, contents, index, expected_policy_digest = expected_bundle(policy_dir, module_dir)
    if policy_digest != expected_policy_digest:
        fail("policy changed while preparing review")
    verify_tree(artifacts_dir, entries, contents)
    if regular_file_bytes(artifacts_dir / "artifact-index.json") != index:
        fail("artifact index changed while preparing review")

    print_review(artifacts_dir, index, policy_digest, bundle_digest)
    entered = input(
        "Type the complete bundle SHA-256 only after completing the review: ").strip()
    if entered != bundle_digest:
        fail("bundle digest did not match; approval was not created")
    write_approval(policy_dir, state_dir, policy_digest, bundle_digest)
    return policy_digest, bundle_digest
