# Findings Reporting

This directory defines the unprivileged output boundary between inventory analysis and human review. Producing a findings report does not grant execution or remediation authority.

Version 1 records:

- inventory provenance and an optional SHA-256 digest,
- analysis engine, model, prompt version, and limitations,
- severity totals,
- stable finding identifiers and lifecycle status,
- confidence and sensitivity classifications,
- JSON Pointer-style evidence locations,
- rationale, impact, recommendation, and references.

Reports should point to the minimum evidence needed to support a finding. Do not copy secrets or unrelated raw inventory into `observation`. A recommendation is text for human review, not an executable command request.

Validate the schema and example with:

```bash
bash modules/audit/tests/test-findings-schema.sh
```
