# AI Auditor Handoff

Date: 2026-08-10

## Goal and design

Build a lightweight home-lab auditor with broad evidence discovery, narrow explicit authority, bounded output, and a small maintenance surface. The current privilege boundary is one root-owned, no-argument inventory collector rather than a general collection of “read-only” Unix commands.

The AI is not trusted as a system administrator. It may analyze broad evidence, but new execution authority must be introduced as fixed, reviewed collectors with explicit escalation points.

## Implemented

- `modules/audit/collect/ai-auditor-inventory.py`
  - Emits schema-versioned JSON.
  - Inventories host, filesystem, network, systemd, accounts, packages, scheduled-task locations, and optional Docker metadata.
  - Uses absolute child executable paths, a fixed environment, closed stdin, isolated process groups, 10-second timeouts, 1 MiB per-stream caps, and item limits.
  - Rejects all command-line arguments.
- `modules/audit/deploy/15-deploy-inventory-collector.sh`
  - Validates Python syntax without writing to the source checkout.
  - Installs a root-owned candidate and atomically renames it into place.
- `modules/audit/configure/enabled-commands.yaml` and `lib/sudoers.sh`
  - Generate one `root:root` collector rule.
  - Emit sudoers `""` so the rule matches no-argument execution only.
- `modules/audit/deploy/30-configure-sudoers.sh`
  - Resolves its artifact path independently of the caller's working directory.
  - Requires `visudo`, installs a root-owned temporary candidate, validates it before activation, and verifies content, ownership, mode, and syntax.
- `modules/audit/tests/`
  - Covers schema, missing and relative commands, timeout behavior, byte truncation, argument rejection, resource ceilings, and the pinned interpreter.
- Documentation now labels the module alpha, distinguishes implemented tests from historical proposals, and includes `modules/audit/docs/THREAT-MODEL.md`.

## Validation completed

Local checks passed:

- Python and shell syntax
- Collector schema and failure-boundary tests
- `git diff --check`
- Generated sudoers parsing with `visudo`

An end-to-end deployment passed inside a disposable Debian 13 container built from the local Hermes image:

- installation from a read-only repository mount,
- root ownership and modes (`0755` collector, `0440` sudoers),
- valid JSON via the allowed sudo command,
- rejection of collector arguments,
- denial of an attempted `/bin/sh`,
- and an exact no-argument rule shown by `sudo -l -U ai-auditor`.

The host VM has an existing `ai-auditor` account and `visudo`, but host deployment was not run because `sudo` requires an interactive password unavailable to this session.

## Hermes review

The live Hermes gateway was queried through its configured free model using only a generic architecture description; private repository contents were not sent to the external Nous Portal. Its review helped identify the need for explicit no-argument sudoers matching and defense-in-depth argument rejection. It also recommended future resource-limit and syscall-level testing.

## Known limitations and next work

1. Repeat end-to-end deployment on the actual target VM and additional supported distributions.
2. Repeat the fixed-command syscall trace on the target VM, including its real systemd and optional Docker paths.
3. Define a versioned findings/report schema that consumes inventory without additional privilege.
4. Add narrow drill-down collectors only when real audit evidence demonstrates a need.
5. Add centralized, tamper-resistant logging before making complete-auditability claims.

The patch archive `ai-auditor-changes-2026-08-10.patch` predates these changes and must not be applied over the current tree.
