"""Verify, display, and record human approval of exact audit bundles."""

from __future__ import annotations

import datetime
import json
import os
import pwd
import shlex
import stat
import sys
import tempfile
from pathlib import Path

from .bundle import (
    POLICY_FILES,
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


def print_paths(paths: list[Path]) -> None:
    for path in paths:
        print(f"[ ] {path}")


def print_field(label: str, value: object) -> None:
    print(f"  {label:<16}: {value}")


def print_review(policy_dir: Path, module_dir: Path, artifacts_dir: Path,
                 index: bytes, policy_digest: str, bundle_digest: str) -> None:
    entries = json.loads(index)["entries"]
    directories = [item for item in entries if item["kind"] == "directory"]
    files = [item for item in entries if item["kind"] == "file"]
    generated = [item for item in files if "generated" in item]
    copied = [item for item in files if "source" in item]
    policy_sources = sorted(
        [policy_dir / policy_name for policy_name, _ in POLICY_FILES.values()]
        + [policy_dir / "schema" / schema_name for _, schema_name in POLICY_FILES.values()])
    runtime_sources = sorted({module_dir / item["source"] for item in copied})
    generated_outputs = [artifacts_dir / "artifact-index.json"] + [
        artifacts_dir / item["bundle_path"] for item in generated]

    print("AI AUDITOR DEPLOYMENT REVIEW")
    print("=" * 28)
    print()
    print("Automated checks establish integrity. Human review establishes trust in")
    print("the code, generated content, and requested installation plan.")
    print()

    heading("AUTOMATED VALIDATION - PASSED")
    print("The review command has already verified that:")
    print("- policy structure and security invariants are valid;")
    print("- the artifact tree and index match a deterministic rebuild;")
    print("- copied files exactly match their validated repository sources;")
    print("- generated files exactly match deterministic generator output; and")
    print("- Python, shell, and sudoers validation succeeded.")
    print()
    print("Any failure above aborts review before an approval prompt is displayed.")
    print()

    heading("HUMAN REVIEW REQUIRED")
    print("1. Use Git to review committed source, policy, compiler, and deployment changes.")
    print("2. Open every path under FILES TO OPEN and decide whether its content is trusted.")
    print("3. Review INSTALLATION PLAN for the intended destinations and permissions.")
    print("4. Approve only after trusting both the file contents and installation plan.")
    print()
    print("The bundle digest binds that judgment to the exact files and metadata shown.")
    print()

    heading("BUNDLE SUMMARY")
    print(f"Installation directories: {len(directories)}")
    print(f"Copied files          : {len(copied)}")
    print(f"Generated files       : {len(generated)}")
    print(f"Total files           : {len(files)}")
    print()

    heading("FILES TO OPEN")
    print("Policy and schema source:")
    print_paths(policy_sources)
    print()
    print("Runtime source copied into the bundle:")
    print_paths(runtime_sources)
    print()
    print("Generated deployment output:")
    print_paths(generated_outputs)
    print()
    heading("INSTALLATION PLAN")
    print("Directories:")
    for item in directories:
        print(f"{item['destination']}")
        print_field("Install as", f"{item['owner']}:{item['group']} {item['mode']}")
        print_field("Bundle path", item["bundle_path"])
    print()
    print("Files:")
    for number, item in enumerate(files, start=1):
        print(f"[{number}/{len(files)}] {item['id']}")
        print_field("Destination", item["destination"])
        print_field("Install as", f"{item['owner']}:{item['group']} {item['mode']}")
        print_field("Bundle path", item["bundle_path"])
        if "source" in item:
            print_field("Origin", f"source {item['source']}")
        else:
            print_field("Origin", f"generator {item['generated']}")
        print_field("Reference SHA-256", item["sha256"])
        print()

    heading("OPTIONAL INDEPENDENT HASH VERIFICATION")
    index_path = artifacts_dir / "artifact-index.json"
    print("The bundle SHA-256 is the SHA-256 of the canonical artifact index.")
    print("To verify it independently, run:")
    print(f"  sha256sum -- {shlex.quote(str(index_path))}")
    print(f"Expected SHA-256: {bundle_digest}")
    print()
    print("To verify an individual artifact, hash its local bundle path and compare")
    print("the result with its Reference SHA-256 in INSTALLATION PLAN.")
    print()

    heading("APPROVAL")
    print(f"Artifact index: {index_path}")
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

    print_review(policy_dir, module_dir, artifacts_dir, index,
                 policy_digest, bundle_digest)
    entered = input(
        "Type the complete bundle SHA-256 only after completing the review: ").strip()
    if entered != bundle_digest:
        fail("bundle digest did not match; approval was not created")
    write_approval(policy_dir, state_dir, policy_digest, bundle_digest)
    return policy_digest, bundle_digest
