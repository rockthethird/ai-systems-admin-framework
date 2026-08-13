#!/usr/bin/env python3
"""Failure-mode tests for the privileged inventory command runner."""

import copy
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
COLLECTOR = Path(sys.argv[1])
sys.path.insert(0, str(COLLECTOR.parent))
import collector_policy

spec = importlib.util.spec_from_file_location("ai_auditor_inventory", COLLECTOR)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def executable(directory: str, name: str, body: str) -> str:
    path = Path(directory) / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def rejected(policy: dict, mutate) -> None:
    candidate = copy.deepcopy(policy)
    mutate(candidate)
    try:
        collector_policy.validate_collector_policy(candidate)
    except ValueError:
        return
    raise AssertionError("collector policy validator accepted an invalid policy")


def main() -> None:
    assert not module.run(["relative-command"])["available"]
    assert not module.run(["/path/that/does/not/exist"])["available"]

    with tempfile.TemporaryDirectory() as directory:
        noisy = executable(directory, "noisy", "while :; do printf '0123456789'; done")
        result = module.run([noisy])
        assert result["available"]
        assert result["truncated"]
        assert sum(len(item.encode()) for item in result["items"]) <= module.MAX_STREAM_BYTES

        sleepy = executable(directory, "sleepy", "sleep 5")
        original_timeout = module.COMMAND_TIMEOUT_SECONDS
        module.COMMAND_TIMEOUT_SECONDS = 0.1
        try:
            result = module.run([sleepy])
        finally:
            module.COMMAND_TIMEOUT_SECONDS = original_timeout
        assert result["available"]
        assert result["error"] == "command timed out"

        limits = module.run([
            "/usr/bin/python3", "-c",
            "import json,resource; print(json.dumps({"
            "'core':resource.getrlimit(resource.RLIMIT_CORE),"
            "'cpu':resource.getrlimit(resource.RLIMIT_CPU),"
            "'file':resource.getrlimit(resource.RLIMIT_FSIZE),"
            "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE)}))",
        ])
        assert limits["exit_code"] == 0
        observed = json.loads(limits["items"][0])
        assert observed["core"] == [0, 0]
        assert observed["cpu"] == [module.MAX_CPU_SECONDS] * 2
        assert observed["file"] == [module.MAX_FILE_BYTES] * 2
        assert observed["nofile"] == [module.MAX_OPEN_FILES] * 2

        manifest = Path(directory) / "manifest.json"
        installed = COLLECTOR.parent.parent / "policy" / "manifest.json"
        policy = json.loads(installed.read_text())
        collector_contract = policy["collectors"]
        collector_policy.validate_collector_policy(collector_contract)
        assert set(module.PRIMITIVES) == set(collector_policy.PRIMITIVE_PARAMETERS)
        rejected(collector_contract,
                 lambda value: value["defaults"].__setitem__("max_items", True))
        rejected(collector_contract,
                 lambda value: value["collectors"][0]["candidates"][0]
                 .__setitem__("path", "relative-command"))
        rejected(collector_contract,
                 lambda value: value["collectors"][-1]["parameters"]["paths"]
                 .__setitem__(0, "../escape"))
        rejected(collector_contract,
                 lambda value: value["collectors"][-1]["parameters"]
                 .__setitem__("unexpected", []))

        policy["collectors"]["collectors"].append(
            dict(policy["collectors"]["collectors"][0]))
        manifest.write_text(json.dumps(policy))
        try:
            module.load_collectors(manifest)
        except ValueError as exc:
            assert "unique" in str(exc)
        else:
            raise AssertionError("collector accepted duplicate manifest IDs")

        policy = json.loads(installed.read_text())
        policy["collectors"]["collectors"][-1]["parameters"]["paths"][0] = "../escape"
        manifest.write_text(json.dumps(policy))
        try:
            module.load_collectors(manifest)
        except ValueError as exc:
            assert "absolute" in str(exc)
        else:
            raise AssertionError("collector accepted an unsafe built-in path")

    print("inventory collector boundary tests passed")


if __name__ == "__main__":
    main()
