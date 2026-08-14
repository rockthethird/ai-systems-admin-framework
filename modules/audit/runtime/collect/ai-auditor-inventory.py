#!/usr/bin/python3
"""Emit a bounded, read-only Linux host inventory as JSON."""

from __future__ import annotations

import json
import os
import platform
import pwd
import resource
import subprocess
import selectors
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from collector_policy import PRIMITIVE_PARAMETERS, validate_collector_policy

SCHEMA_VERSION = "1.0"
MANIFEST_VERSION = "ai-auditor-policy-manifest/v1"
MANIFEST_PATH = Path(__file__).resolve().parent.parent / "policy" / "manifest.json"
COMMAND_TIMEOUT_SECONDS = 10
MAX_LINES = 5000
MAX_STREAM_BYTES = 1024 * 1024
MAX_CPU_SECONDS = 5
MAX_OPEN_FILES = 256
MAX_FILE_BYTES = 1024 * 1024
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
def unavailable(error: str = "command not found") -> dict[str, Any]:
    return {"available": False, "items": [], "truncated": False, "exit_code": None, "error": error}


def limit_child_resources() -> None:
    """Apply conservative limits in the child immediately before exec."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE_BYTES, MAX_FILE_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))


def run(command: list[str], max_lines: int = MAX_LINES) -> dict[str, Any]:
    """Run a fixed command while bounding time and captured output."""
    if not command or not os.path.isabs(command[0]):
        return unavailable("collector command must use an absolute path")
    if not os.access(command[0], os.X_OK):
        return unavailable()

    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = False
    timed_out = False
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=SAFE_ENV, start_new_session=True,
            preexec_fn=limit_child_resources,
        )
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(timeout=remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                room = MAX_STREAM_BYTES - len(buffer)
                if room > 0:
                    buffer.extend(chunk[:room])
                if len(chunk) > room:
                    truncated = True
                    break
            if truncated:
                break
        if timed_out or truncated:
            os.killpg(process.pid, signal.SIGKILL)
        exit_code = process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        return unavailable(str(exc)[:1000])
    finally:
        selector.close()

    stdout = buffers["stdout"].decode("utf-8", errors="replace")
    stderr = buffers["stderr"].decode("utf-8", errors="replace").strip()
    lines = stdout.splitlines()
    return {"available": True, "items": lines[:max_lines],
            "truncated": truncated or len(lines) > max_lines, "exit_code": exit_code,
            "error": "command timed out" if timed_out else (stderr[:1000] or None)}


def first_available(commands: list[list[str]], max_lines: int = MAX_LINES) -> dict[str, Any]:
    for command in commands:
        result = run(command, max_lines)
        if result["available"]:
            return result
    return unavailable()


def read_os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values


def path_metadata(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
        return {"path": str(path), "exists": True, "mode": oct(stat.st_mode & 0o7777),
                "uid": stat.st_uid, "gid": stat.st_gid}
    except OSError:
        return {"path": str(path), "exists": False, "mode": None, "uid": None, "gid": None}


def available(items: Any) -> dict[str, Any]:
    return {"available": True, "items": items, "truncated": False,
            "exit_code": 0, "error": None}


def collect_passwd_entries(_parameters: dict[str, Any]) -> dict[str, Any]:
    items = [{"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid,
              "home": entry.pw_dir, "shell": entry.pw_shell}
             for entry in pwd.getpwall()[:MAX_LINES]]
    return available(items)


def collect_host_platform(_parameters: dict[str, Any]) -> dict[str, Any]:
    return available({"hostname": platform.node(), "kernel": platform.release(),
                      "architecture": platform.machine()})


def collect_os_release(_parameters: dict[str, Any]) -> dict[str, Any]:
    return available(read_os_release())


def collect_path_metadata(parameters: dict[str, Any]) -> dict[str, Any]:
    return available([path_metadata(Path(path)) for path in parameters["paths"]])


def collect_ssh_settings(parameters: dict[str, Any]) -> dict[str, Any]:
    paths = parameters["executable_paths"]
    settings_wanted = set(parameters["settings"])
    sshd = next((path for path in paths if os.access(path, os.X_OK)), None)
    if sshd is None:
        return unavailable("sshd not found")
    users = []
    for name in parameters["users"]:
        result = run([sshd, "-T", "-C", f"user={name},host=localhost,addr=127.0.0.1"])
        settings = {}
        if result["available"] and result["exit_code"] == 0 and not result["truncated"]:
            for line in result["items"]:
                key, _, value = line.partition(" ")
                if key in settings_wanted:
                    settings[key] = value.strip()
        users.append({"name": name, "available": set(settings) == settings_wanted,
                      "settings": settings})
    if not all(user["available"] for user in users):
        return unavailable("effective SSH settings were incomplete")
    return available(users)


def collect_account_paths(parameters: dict[str, Any]) -> dict[str, Any]:
    result = []
    users = parameters["users"]
    accounts = {entry.pw_name: entry for entry in pwd.getpwall() if entry.pw_name in users}
    for name in users:
        entry = accounts.get(name)
        if entry is None:
            result.append({"name": name, "exists": False, "uid": None, "shell": None,
                           "home": None, "paths": {}})
            continue
        home = Path(entry.pw_dir)
        result.append({"name": name, "exists": True, "uid": entry.pw_uid,
                       "shell": entry.pw_shell, "home": entry.pw_dir,
                       "home_metadata": path_metadata(home),
                       "paths": {relative: path_metadata(home / relative)
                                 for relative in parameters["relative_paths"]}})
    return available(result)


PRIMITIVES = {
    "passwd-entries": collect_passwd_entries,
    "host-platform": collect_host_platform,
    "os-release": collect_os_release,
    "identity-endpoint-metadata": collect_path_metadata,
    "path-metadata": collect_path_metadata,
    "ssh-effective-settings": collect_ssh_settings,
    "account-path-metadata": collect_account_paths,
}
if set(PRIMITIVES) != set(PRIMITIVE_PARAMETERS):
    raise RuntimeError("collector primitive implementations do not match policy contract")


def load_collectors(manifest_path: Path) -> tuple[dict[str, int], list[dict[str, Any]]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise ValueError("unsupported audit policy manifest")
    policy = manifest.get("collectors")
    validate_collector_policy(policy)
    return policy["defaults"], policy["collectors"]


def configure_limits(defaults: dict[str, int]) -> None:
    global COMMAND_TIMEOUT_SECONDS, MAX_LINES, MAX_STREAM_BYTES
    global MAX_CPU_SECONDS, MAX_OPEN_FILES, MAX_FILE_BYTES
    COMMAND_TIMEOUT_SECONDS = defaults["command_timeout_seconds"]
    MAX_LINES = defaults["max_items"]
    MAX_STREAM_BYTES = defaults["max_stream_bytes"]
    MAX_CPU_SECONDS = defaults["max_cpu_seconds"]
    MAX_OPEN_FILES = defaults["max_open_files"]
    MAX_FILE_BYTES = defaults["max_file_bytes"]


def collect(manifest_path: Path) -> dict[str, Any]:
    defaults, policy = load_collectors(manifest_path)
    configure_limits(defaults)
    results = {}
    for collector in policy:
        if collector["type"] == "command":
            commands = [[candidate["path"], *candidate["args"]]
                        for candidate in collector["candidates"]]
            results[collector["id"]] = first_available(
                commands, collector.get("max_items", MAX_LINES))
        else:
            results[collector["id"]] = PRIMITIVES[collector["primitive"]](
                collector.get("parameters", {}))
        results[collector["id"]]["required"] = not collector.get("optional", False)
    return {"schema_version": SCHEMA_VERSION,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "limits": {"command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
                       "max_items_per_command": MAX_LINES,
                       "max_bytes_per_stream": MAX_STREAM_BYTES,
                       "max_cpu_seconds": MAX_CPU_SECONDS,
                       "max_open_files": MAX_OPEN_FILES,
                       "max_file_bytes": MAX_FILE_BYTES},
            "collectors": results}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("ai-auditor-inventory does not accept arguments")
    json.dump(collect(MANIFEST_PATH), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
