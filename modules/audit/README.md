# AI Auditor

Experimental, least-privilege host inventory for AI-assisted auditing.

## Current capability

The module creates an `ai-auditor` service account and grants it one privileged operation: execute `/usr/local/libexec/ai-auditor-inventory` with no arguments. The collector emits bounded JSON describing host identity, filesystems, networking, systemd, accounts, packages, scheduled-task locations, and—when the Docker client and daemon access are available—container metadata.

This is an inventory and evidence-collection layer. Finding generation, adaptive drill-down, reporting, and remediation are not implemented yet. The module is alpha software and is not production-ready.

## Security model

- Broad discovery is implemented inside one root-owned, fixed collector.
- Sudo permits the exact collector path as `root:root`; arbitrary commands and arguments are not granted.
- Child commands use absolute paths, a fixed environment, a timeout, and byte/item output limits.
- Collector and sudoers deployments validate a temporary candidate before atomic activation.
- SSH and sudo logs provide evidence, but complete centralized auditability is not yet implemented.

The collector is privileged code. Its output can contain sensitive host, account, network, package, and container metadata. Docker daemon access is optional and must be reviewed separately. See [THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Build, deploy, and test

```bash
# On the controller
bash modules/audit/build/10-generate-sudoers-from-yaml.sh
bash modules/audit/tests/test-inventory-collector.sh
bash modules/audit/tests/test-sudoers-generation.sh

# On a disposable target, from the repository root
sudo bash modules/audit/deploy/10-create-user.sh
sudo bash modules/audit/deploy/15-deploy-inventory-collector.sh
sudo bash modules/audit/deploy/30-configure-sudoers.sh

# Positive and negative authorization checks
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-inventory
sudo -u ai-auditor sudo -n /bin/sh -c id   # must be denied
```

SSH key setup and SSH hardening are separate steps; see [deploy/README.md](deploy/README.md). Test on a snapshot or disposable host before wider use.

## Next milestones

1. Repeat end-to-end deployment and denial testing on supported Linux distributions.
2. Define a versioned findings/report schema that consumes inventory without more privilege.
3. Add drill-down collectors only when real audits identify missing evidence.
4. Add centralized, tamper-resistant logging before making stronger auditability claims.
