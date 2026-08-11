# AI Auditor Handoff

Date: 2026-08-10

## Goal and design

Build a lightweight home-lab auditor with broad evidence discovery, narrow explicit authority, bounded output, and a small maintenance surface. The current AI-facing privilege boundary is one root-owned, no-argument sanitized report endpoint rather than a general collection of “read-only” Unix commands.

The AI is not trusted as a system administrator. It may analyze broad evidence, but new execution authority must be introduced as fixed, reviewed collectors with explicit escalation points.

## Implemented

- `modules/audit/collect/ai-auditor-inventory.py`
  - Emits schema-versioned JSON.
  - Inventories host, filesystem, network, systemd, accounts, packages, scheduled-task locations, and optional Docker metadata.
  - Uses absolute child executable paths, a fixed environment, closed stdin, isolated process groups, 10-second timeouts, 1 MiB per-stream caps, and item limits.
  - Rejects all command-line arguments.
- `modules/audit/deploy/15-deploy-inventory-collector.sh`
  - Validates Python and shell syntax without writing to the source checkout.
  - Installs the collector, analyzer, and sanitizer as root-only helpers and activates the public report endpoint last.
- `modules/audit/configure/enabled-commands.yaml` and `lib/sudoers.sh`
  - Generate one `root:root` sanitized report rule; the raw collector is absent.
  - Emit sudoers `""` so the rule matches no-argument execution only.
- `modules/audit/deploy/30-configure-sudoers.sh`
  - Resolves its artifact path independently of the caller's working directory.
  - Requires `visudo`, installs a root-owned temporary candidate, validates it before activation, and verifies content, ownership, mode, and syntax.
- `modules/audit/tests/`
  - Covers schema, missing and relative commands, timeout behavior, byte truncation, argument rejection, resource ceilings, and the pinned interpreter.
- Documentation now labels the module alpha, distinguishes implemented tests from historical proposals, and includes `modules/audit/docs/THREAT-MODEL.md`.
- `modules/audit/reporting/` defines the unprivileged `ai-auditor-findings/v1` report contract, provenance, evidence pointers, confidence, sensitivity, and lifecycle fields.
- `modules/audit/reporting/analyze-inventory.py` publishes explicit passed, failed, and unknown outcomes for nine deterministic controls covering capacity, failed services, UID 0 identities, evidence completeness, effective SSH authentication, auditor shells and paths, and report-endpoint integrity.
- `modules/audit/reporting/sanitize-findings.py` produces a fail-closed `external-safe/v1` view for Hermes. It withholds host identifiers, timestamps, raw evidence, and JSON pointers while retaining controlled rule text, severity, confidence, hashes, evidence counts, and completeness.
- `modules/audit/reporting/prepare-external-report.sh` runs local analysis followed by sanitization so raw inventory and evidence-rich findings do not enter the normal model-facing workflow.
- `modules/audit/reporting/ai-auditor-report.sh` is the installed AI-facing endpoint. It creates root-only temporary evidence, calls the private collector/analyzer/sanitizer chain, emits only external-safe JSON, and removes intermediate artifacts on exit.
- `modules/audit/reporting/ai-auditor-report-internal.sh` emits `internal-rich/v1` for a local model, including exact host identity and constrained finding-relevant evidence labeled as untrusted.
- `modules/audit/deploy/12-create-report-identities.sh` creates locked `ai-auditor-cloud` and `ai-auditor-local` identities without installing SSH keys. Sudo binds each identity to only its matching fixed endpoint; SSH binding is deliberately deferred for design review.
- `modules/audit/policy/` is now the primary human-review surface for collectors, rules, disclosure profiles, and identity bindings. Strict schemas and `build/compile-policy.py` produce a deterministic checked-in manifest; YAML cannot contain shell fragments or arbitrary expressions.
- The analyzer and both sanitizers load public control definitions from that root-owned manifest. Shared fail-closed validation removes duplicated rule text and coverage logic while profile-specific evidence reduction remains explicit.

## Validation completed

Local checks passed:

- Python and shell syntax
- Collector schema and failure-boundary tests
- `git diff --check`
- Generated sudoers parsing with `visudo`

The original raw collector boundary passed end-to-end deployment inside a disposable Debian 13 container built from the local Hermes image. The current sanitized endpoint was then deployed and tested directly on the disposable VM host:

- root-only modes (`0700`) for the collector, analyzer, and sanitizer,
- `0755` for the public report endpoint and `0440` for sudoers,
- valid `ai-auditor-external-findings/v1` through the allowed sudo command,
- absence of the VM hostname and raw evidence from the returned document,
- direct and sudo denial of the raw collector,
- rejection of report arguments and denial of an attempted `/bin/sh`,
- and an exact report-only rule shown by `sudo -l -U ai-auditor`.

The expanded nine-rule endpoint was deployed on 2026-08-11. Both profiles reported six passed and three failed controls with no unknowns. The live failures were password-capable SSH authentication, direct root SSH login, and interactive shells for the two report identities. Endpoint ownership and auditor path permissions passed. External-safe leakage checks and cross-profile/raw-collector denial checks also passed.

The declarative-policy reporting migration was then deployed with semantic before/after comparison. After removing only per-run hashes and collection timestamps, both external-safe and internal-rich JSON were identical. All policy compilation, stale-artifact, duplicate-ID, weakened-disclosure, review-surface, reporting, collector, schema, and sudoers tests passed.

## Hermes review

The live Hermes gateway was queried through its configured free model using only a generic architecture description; private repository contents were not sent to the external Nous Portal. Its review helped identify the need for explicit no-argument sudoers matching and defense-in-depth argument rejection. It also recommended future resource-limit and syscall-level testing.

Hermes currently runs on the audited host with direct Docker and SSH paths only for framework development and testing. That topology can bypass a sanitization wrapper and must not be treated as the intended production boundary. When Hermes is given access to other servers, those targets should expose only framework-defined collection, analysis, sanitization, and approved drill-down capabilities.

## Known limitations and next work

1. Repeat end-to-end deployment on additional supported distributions and future remote targets.
2. Repeat the fixed-command syscall trace on the target VM, including its real systemd and optional Docker paths.
3. Move fixed command definitions and hard-coded collector limits behind the validated collector policy while retaining resource ceilings in trusted code.
4. Generate sudoers from identity policy, then decide and implement SSH forced-command and key binding.
5. Add narrow drill-down collectors only when real audit evidence demonstrates a need.
6. Add centralized, tamper-resistant logging before making complete-auditability claims.

The patch archive `ai-auditor-changes-2026-08-10.patch` predates these changes and must not be applied over the current tree.
