# AI Auditor

Experimental, least-privilege host inventory for AI-assisted auditing.

## Current capability

The module creates separate locked `ai-auditor-cloud` and `ai-auditor-local` identities. Cloud can execute only the no-argument external-safe endpoint; local can execute only the no-argument internal-rich endpoint. Both collect bounded evidence through root-only helpers, and neither identity can execute or sudo the raw collector.

The report includes explicit passed, failed, and unknown outcomes for nine deterministic controls, including effective SSH policy and the integrity of the report access boundary. Adaptive drill-down and remediation are not implemented. The module is alpha software and is not production-ready.

## Security model

- Broad discovery is implemented inside one root-only, fixed collector.
- Sudo permits the exact sanitized report endpoint as `root:root`; arbitrary commands, arguments, and raw collection are not granted.
- Child commands use absolute paths, a fixed environment, a timeout, and byte/item output limits.
- Collector and sudoers deployments validate a temporary candidate before atomic activation.
- SSH and sudo logs provide evidence, but complete centralized auditability is not yet implemented.

The collector is privileged code. Its output can contain sensitive host, account, network, package, and container metadata. Docker daemon access is optional and must be reviewed separately. See [THREAT-MODEL.md](docs/THREAT-MODEL.md).

The fixed child-command review and current trace limitations are recorded in [COLLECTOR-COMMAND-REVIEW.md](docs/COLLECTOR-COMMAND-REVIEW.md).

## Build, deploy, and test

```bash
# On the controller
bash modules/audit/build/10-generate-sudoers-from-yaml.sh
bash modules/audit/tests/test-inventory-collector.sh
bash modules/audit/tests/test-sudoers-generation.sh
bash modules/audit/tests/test-findings-schema.sh
bash modules/audit/tests/test-inventory-analysis.sh
bash modules/audit/tests/test-external-findings-sanitization.sh
bash modules/audit/tests/test-internal-findings-sanitization.sh

# On a disposable target, from the repository root
sudo bash modules/audit/deploy/12-create-report-identities.sh
sudo bash modules/audit/deploy/15-deploy-inventory-collector.sh
sudo bash modules/audit/deploy/30-configure-sudoers.sh

# Positive and negative authorization checks
sudo -u ai-auditor-cloud sudo -n /usr/local/libexec/ai-auditor-report
sudo -u ai-auditor-local sudo -n /usr/local/libexec/ai-auditor-report-internal
sudo -u ai-auditor-cloud sudo -n /usr/local/libexec/ai-auditor-inventory  # must be denied
```

SSH key setup and SSH hardening are separate steps; see [deploy/README.md](deploy/README.md). Test on a snapshot or disposable host before wider use.

## Next milestones

1. Repeat end-to-end deployment and denial testing on supported Linux distributions.
2. Bind separate SSH credentials and forced commands to the cloud and local report identities.
3. Exercise the external-safe report wrapper through Hermes without exposing raw inventory.
4. Add drill-down collectors only when real audits identify missing evidence.
5. Add centralized, tamper-resistant logging before making stronger auditability claims.

The local and external-safe report contracts are documented in [reporting/README.md](reporting/README.md).
