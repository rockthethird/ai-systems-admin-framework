# Getting started

The repository currently contains an alpha audit module. It collects bounded
Linux host evidence, evaluates deterministic controls locally, and exposes
identity-bound sanitized JSON reports. It does not yet configure SSH access,
perform remediation, or provide production-grade centralized audit logging.

## Review the security model

Start with:

```text
modules/audit/README.md
modules/audit/docs/THREAT-MODEL.md
modules/audit/docs/ARCHITECTURE-DECLARATIVE-POLICY.md
```

The primary behavior review surface is:

```text
modules/audit/policy/collectors.yaml
modules/audit/policy/rules.yaml
modules/audit/policy/profiles.yaml
modules/audit/policy/identities.yaml
```

YAML selects constrained named primitives. It cannot embed shell commands,
templates, regular expressions, Python, or arbitrary expressions.

## Validate a checkout

From the repository root:

```bash
python3 modules/audit/build/compile-policy.py --check

for test in modules/audit/tests/test-*.sh; do
    bash "$test"
done
```

These tests cover policy compilation, stale generated artifacts, collector
bounds, deterministic reports, sanitized disclosure, and sudoers generation.
They do not replace live authorization testing on each target platform.

## Deploy to a disposable target

Use a snapshot-backed or disposable Linux host:

```bash
sudo bash modules/audit/deploy/12-create-report-identities.sh
sudo bash modules/audit/deploy/15-deploy-inventory-collector.sh
bash modules/audit/build/10-generate-sudoers-from-yaml.sh
sudo bash modules/audit/deploy/30-configure-sudoers.sh
```

Then follow the positive and negative checks in
`modules/audit/deploy/README.md`.

Stop before SSH configuration. Key installation and forced-command binding are
not implemented. The removed legacy scripts targeted a superseded identity and
must not be recovered from Git history as deployment instructions.

## Interpret reports

- `external-safe/v1` is minimized for an externally hosted model. It excludes
  host identity, timestamps, raw inventory, paths, and evidence values.
- `internal-rich/v1` is intended for a local model. It includes constrained
  finding-relevant details labeled as untrusted host evidence.

Neither report grants execution or remediation authority. The current
Hermes-on-audited-host topology has Docker access and is only a development
test; it is not evidence of a confidentiality boundary.

## Continue development

Read `CONTRIBUTING.md`. Add ordinary behavior through reviewed policy and named
primitives. Do not add a raw collector, shell, interpreter, pager, editor,
generic file reader, package manager, container command, or caller-controlled
argument to sudoers.
