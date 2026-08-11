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

SCHEMA_VERSION = "1.0"
COMMAND_TIMEOUT_SECONDS = 10
MAX_LINES = 5000
MAX_STREAM_BYTES = 1024 * 1024
MAX_CPU_SECONDS = 5
MAX_OPEN_FILES = 256
MAX_FILE_BYTES = 1024 * 1024
SAFE_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
AUDITOR_USERS = ("ai-auditor-cloud", "ai-auditor-local")
REPORT_PATHS = ("/usr/local/libexec/ai-auditor-report", "/usr/local/libexec/ai-auditor-report-internal")
SSH_SETTINGS = {"passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication", "permitrootlogin"}


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


def task_paths() -> list[dict[str, Any]]:
    paths = [Path("/etc/crontab"), Path("/etc/cron.d"), Path("/etc/cron.daily"),
             Path("/etc/cron.hourly"), Path("/etc/cron.weekly"), Path("/etc/cron.monthly")]
    result = []
    for path in paths:
        try:
            stat = path.stat()
            result.append({"path": str(path), "mode": oct(stat.st_mode & 0o7777), "uid": stat.st_uid, "gid": stat.st_gid})
        except OSError:
            continue
    return result


def path_metadata(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
        return {"path": str(path), "exists": True, "mode": oct(stat.st_mode & 0o7777),
                "uid": stat.st_uid, "gid": stat.st_gid}
    except OSError:
        return {"path": str(path), "exists": False, "mode": None, "uid": None, "gid": None}


def ssh_posture() -> dict[str, Any]:
    sshd = next((path for path in ("/usr/sbin/sshd", "/sbin/sshd") if os.access(path, os.X_OK)), None)
    if sshd is None:
        return {"available": False, "users": [], "error": "sshd not found"}
    users = []
    for name in AUDITOR_USERS:
        result = run([sshd, "-T", "-C", f"user={name},host=localhost,addr=127.0.0.1"])
        settings = {}
        if result["available"] and result["exit_code"] == 0 and not result["truncated"]:
            for line in result["items"]:
                key, _, value = line.partition(" ")
                if key in SSH_SETTINGS:
                    settings[key] = value.strip()
        users.append({"name": name, "available": set(settings) == SSH_SETTINGS, "settings": settings})
    return {"available": all(user["available"] for user in users), "users": users, "error": None}


def auditor_paths() -> list[dict[str, Any]]:
    result = []
    accounts = {entry.pw_name: entry for entry in pwd.getpwall() if entry.pw_name in AUDITOR_USERS}
    for name in AUDITOR_USERS:
        entry = accounts.get(name)
        if entry is None:
            result.append({"name": name, "exists": False, "uid": None, "shell": None, "home": None,
                           "home_metadata": None, "authorized_keys_metadata": None})
            continue
        home = Path(entry.pw_dir)
        result.append({"name": name, "exists": True, "uid": entry.pw_uid, "shell": entry.pw_shell, "home": entry.pw_dir,
                       "home_metadata": path_metadata(home),
                       "authorized_keys_metadata": path_metadata(home / ".ssh" / "authorized_keys")})
    return result


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("ai-auditor-inventory does not accept arguments")
    accounts = [{"name": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid,
                 "home": entry.pw_dir, "shell": entry.pw_shell} for entry in pwd.getpwall()[:MAX_LINES]]
    packages = first_available([["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n"],
                                ["/usr/bin/rpm", "-qa"], ["/bin/rpm", "-qa"]])
    inventory = {
        "schema_version": SCHEMA_VERSION, "collected_at": datetime.now(timezone.utc).isoformat(),
        "limits": {"command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
                   "max_items_per_command": MAX_LINES,
                   "max_bytes_per_stream": MAX_STREAM_BYTES,
                   "max_cpu_seconds": MAX_CPU_SECONDS,
                   "max_open_files": MAX_OPEN_FILES,
                   "max_file_bytes": MAX_FILE_BYTES},
        "host": {"hostname": platform.node(), "kernel": platform.release(), "architecture": platform.machine(),
                 "os_release": read_os_release(), "uptime": first_available([["/usr/bin/uptime", "-p"], ["/bin/uptime", "-p"]], 10)},
        "filesystems": first_available([["/usr/bin/df", "-P", "-T"], ["/bin/df", "-P", "-T"]]),
        "network": {"interfaces": first_available([["/usr/sbin/ip", "-details", "address"], ["/sbin/ip", "-details", "address"]]),
                    "routes": first_available([["/usr/sbin/ip", "route", "show", "table", "all"], ["/sbin/ip", "route", "show", "table", "all"]]),
                    "listening_sockets": first_available([["/usr/bin/ss", "-H", "-lntup"], ["/bin/ss", "-H", "-lntup"]])},
        "systemd": {"failed_units": first_available([["/usr/bin/systemctl", "--no-pager", "--plain", "--failed"], ["/bin/systemctl", "--no-pager", "--plain", "--failed"]]),
                    "timers": first_available([["/usr/bin/systemctl", "--no-pager", "--plain", "list-timers", "--all"], ["/bin/systemctl", "--no-pager", "--plain", "list-timers", "--all"]]),
                    "enabled_units": first_available([["/usr/bin/systemctl", "--no-pager", "--plain", "list-unit-files", "--state=enabled"], ["/bin/systemctl", "--no-pager", "--plain", "list-unit-files", "--state=enabled"]])},
        "accounts": accounts, "packages": packages,
        "security": {"ssh": ssh_posture(), "auditor_accounts": auditor_paths(),
                     "report_endpoints": [path_metadata(Path(path)) for path in REPORT_PATHS]},
        # Docker daemon visibility is sensitive and intentionally optional.
        "containers": first_available([["/usr/bin/docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}"],
                                       ["/usr/local/bin/docker", "ps", "--all", "--no-trunc", "--format", "{{json .}}"]]),
        "scheduled_tasks": task_paths(),
    }
    json.dump(inventory, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
