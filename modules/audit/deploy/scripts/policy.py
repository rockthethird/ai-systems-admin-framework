#!/usr/bin/python3
"""Build, review, and verify deterministic audit deployment artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

import jsonschema
import yaml

from policy_support.approval import human_approval_status, review, verify
from policy_support.bundle import build


def parse_args() -> argparse.Namespace:
    deploy_dir = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    def paths(command: argparse.ArgumentParser) -> None:
        command.add_argument("--policy-dir", type=Path, default=deploy_dir / "policy")
        command.add_argument("--module-dir", type=Path, default=deploy_dir.parent)
        command.add_argument("--artifacts-dir", type=Path, default=deploy_dir / "artifacts")
        command.add_argument("--state-dir", type=Path, default=deploy_dir / ".state")

    paths(commands.add_parser("build", help="build and validate deployment artifacts"))
    paths(commands.add_parser("verify", help="verify the bundle and its approval"))
    paths(commands.add_parser("review", help="review and approve exact artifact bytes"))
    return parser.parse_args()


def print_result(policy_digest: str, bundle_digest: str, approval_status: str) -> None:
    print(f"policy_sha256: {policy_digest}")
    print(f"bundle_sha256: {bundle_digest}")
    print(f"human_approval_status: {approval_status}")


def main() -> int:
    args = parse_args()
    try:
        if args.command == "build":
            policy_digest, bundle_digest = build(
                args.policy_dir, args.module_dir, args.artifacts_dir)
            status = human_approval_status(
                args.policy_dir, args.state_dir, policy_digest, bundle_digest)
        elif args.command == "verify":
            policy_digest, bundle_digest = verify(
                args.policy_dir, args.module_dir, args.artifacts_dir, args.state_dir)
            status = "MATCHED"
        else:
            policy_digest, bundle_digest = review(
                args.policy_dir, args.module_dir, args.artifacts_dir, args.state_dir)
            status = "MATCHED"
        print_result(policy_digest, bundle_digest, status)
    except (OSError, ValueError, yaml.YAMLError, json.JSONDecodeError,
            jsonschema.SchemaError, jsonschema.ValidationError) as exc:
        print(f"policy command failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
