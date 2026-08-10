# Collector Command and Syscall Review

Date: 2026-08-10

## Scope

This review covers the fixed child commands executed by `ai-auditor-inventory.py`. It is evidence about one disposable Debian 13 environment, not a guarantee for every utility version or target distribution.

The collector was installed from a read-only repository mount into a fresh container based on the local Hermes image. The installed entrypoint was traced recursively with `strace` while its JSON output was separately validated.

## Observed executables

- `/usr/bin/df -P -T`
- `/usr/bin/docker ps --all --no-trunc --format {{json .}}`
- `/usr/bin/dpkg-query -W ...`
- `/usr/bin/ss -H -lntup`
- `/usr/bin/uptime -p`
- `/usr/sbin/ip -details address`
- `/usr/sbin/ip route show table all`

`systemctl` was unavailable in this image and remains target-host validation work. RPM fallback commands were not selected because `dpkg-query` was available.

## Results

No child opened a regular file with `O_WRONLY`, `O_CREAT`, `O_TRUNC`, or `O_APPEND`. The only `O_RDWR` opens were the collector's intentional `/dev/null` handles for closed child stdin.

Observed Unix-socket connection attempts were:

- `/var/run/nscd/socket`, which was absent; and
- `/var/run/docker.sock`, which was absent in the test container.

Network inventory uses netlink through `ip` and `ss`. Docker inventory intentionally contacts the local Docker daemon when both the client and socket access are available. These are expected observation channels, but Docker remains a separate sensitive trust boundary.

The trace also exposed PATH-based resolution of the collector's original `env python3` shebang. The privileged entrypoint was subsequently pinned to `/usr/bin/python3`, with installer and regression-test enforcement.

## Configuration influence

The collector gives children only `PATH`, `LANG`, and `LC_ALL`; it does not forward caller-controlled Docker, systemd, Python, loader, or home variables. Fixed utilities may still read system-level configuration compiled into or discovered by those programs. Those files and binaries are part of the trusted host base and must remain root-owned and non-writable by the auditor account.

## Remaining validation

1. Repeat tracing on the target VM with its real `systemctl`, RPM/dpkg selection, and utility versions.
2. Repeat Docker tracing only after explicitly approving access to the target daemon.
3. Compare traces after operating-system upgrades that materially change a fixed utility.
4. Investigate syscall confinement only after the real target traces establish a stable allowlist.
