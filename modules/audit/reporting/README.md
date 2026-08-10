# Findings Reporting

This directory defines two unprivileged output boundaries:

1. `ai-auditor-findings/v1` preserves evidence for local human review.
2. `ai-auditor-external-findings/v1` minimizes disclosure before findings enter an externally hosted model workflow such as Hermes.
3. `ai-auditor-internal-findings/v1` supplies a local model with exact host identity and narrowly parsed, finding-relevant evidence while still withholding raw inventory and arbitrary evidence text.

Producing either report grants no execution or remediation authority.

Version 1 records:

- inventory provenance and an optional SHA-256 digest,
- analysis engine, model, prompt version, and limitations,
- severity totals,
- stable finding identifiers and lifecycle status,
- confidence and sensitivity classifications,
- JSON Pointer-style evidence locations,
- rationale, impact, recommendation, and references.

Reports should point to the minimum evidence needed to support a finding. Do not copy secrets or unrelated raw inventory into `observation`. A recommendation is text for human review, not an executable command request.

## External-safe profile

Raw inventory and full findings remain local. Generate the model-facing document with:

```bash
modules/audit/reporting/prepare-external-report.sh inventory.json > external-findings.json
```

The wrapper analyzes the raw inventory locally, stores its intermediate findings in a mode-restricted temporary file, and emits only the `external-safe/v1` view. Do not give raw inventory or full findings to Hermes before running this step.

The external-safe sanitizer:

- accepts only reports from `ai-auditor-static-rules/v1`,
- reconstructs public text for known rule IDs rather than copying arbitrary report strings,
- rejects unknown rules, altered public text, duplicate IDs, and inconsistent summaries,
- withholds host identity, collection timestamps, evidence paths, and evidence observations,
- retains content hashes, severity totals, confidence, controlled evidence sections, and withheld-item counts,
- marks evidence quality degraded when the analyzer reports incomplete collection.

This is a default data-minimization guardrail. It becomes a hard confidentiality boundary only when Hermes cannot bypass it through unrestricted SSH, Docker, filesystem, or other host access.

On a deployed target, Hermes does not call the raw collector or this controller-side helper directly. Its sole privileged command is:

```bash
sudo -n /usr/local/libexec/ai-auditor-report
```

The installed endpoint creates root-only temporary inventory and findings, runs the private collector/analyzer/sanitizer chain, emits only the external-safe document, and removes intermediates on exit. The raw collector and reporting helpers are installed `root:root 0700` and are absent from sudoers.

The separate local-model identity calls:

```bash
sudo -n /usr/local/libexec/ai-auditor-report-internal
```

Its `internal-rich/v1` output includes the exact hostname, collection time, evidence pointers, and constrained details such as affected mount points, unit names, and account names. Every detail is labeled `untrusted_host_evidence`; raw observations, arbitrary errors, logs, configuration contents, and unrelated inventory remain excluded.

Profiles are bound to separate operating-system identities, not selected by caller arguments:

- `ai-auditor-cloud` can run only the external-safe endpoint.
- `ai-auditor-local` can run only the internal-rich endpoint.
- The legacy `ai-auditor` identity has no report sudo capability after migration.

SSH keys and forced-command bindings are intentionally not configured yet.

Validate the schema and example with:

```bash
bash modules/audit/tests/test-findings-schema.sh
bash modules/audit/tests/test-inventory-analysis.sh
bash modules/audit/tests/test-external-findings-sanitization.sh
bash modules/audit/tests/test-internal-findings-sanitization.sh
```

Generate an initial deterministic report without elevated privileges:

```bash
modules/audit/reporting/analyze-inventory.py inventory.json --output findings.json
```

The initial static rules flag filesystems at or above 90% utilization, failed systemd units, additional UID 0 accounts, and incomplete collection evidence. Rule IDs are stable. The analyzer and sanitizer perform no subprocess or network operations. The controller helper invokes those two pinned local programs; the installed endpoint additionally invokes the fixed root-only collector.
