#!/usr/bin/env python3
"""Failure-mode tests for the privileged inventory command runner."""

import importlib.util
import tempfile
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parent.parent / "collect" / "ai-auditor-inventory.py"
spec = importlib.util.spec_from_file_location("ai_auditor_inventory", COLLECTOR)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def executable(directory: str, name: str, body: str) -> str:
    path = Path(directory) / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


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

    print("inventory collector boundary tests passed")


if __name__ == "__main__":
    main()
