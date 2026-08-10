# Deploy the AI auditor

Run deployment against a snapshot-backed or disposable Linux target. The scripts assume the repository is present on that target unless noted otherwise.

## Sequence

```bash
# Target: create the service account
sudo bash modules/audit/deploy/10-create-user.sh

# Target: install root-only audit helpers and the sanitized endpoint
sudo bash modules/audit/deploy/15-deploy-inventory-collector.sh

# Controller: optionally provision the SSH key
bash modules/audit/deploy/20-setup-ssh-keys.sh -s admin@target

# Target: apply the reviewed SSH restrictions
sudo bash modules/audit/deploy/25-harden-ssh-config.sh

# Controller: regenerate and review sudoers
bash modules/audit/build/10-generate-sudoers-from-yaml.sh

# Target: validate a root-owned candidate and activate it atomically
sudo bash modules/audit/deploy/30-configure-sudoers.sh
```

The sudoers deployment requires `visudo`; skipping validation is not an acceptable production path.

## Verify

```bash
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-report > /tmp/external-findings.json
python3 -m json.tool /tmp/external-findings.json >/dev/null

# These must fail.
sudo -u ai-auditor /usr/local/libexec/ai-auditor-inventory
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-inventory
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-report unexpected
sudo -u ai-auditor sudo -n /bin/sh -c id

sudo visudo -c -f /etc/sudoers.d/ai-auditor
sudo stat -c '%U:%G %a %n' /usr/local/libexec/ai-auditor-{inventory,analyze-inventory,sanitize-findings,report} /etc/sudoers.d/ai-auditor
sudo -l -U ai-auditor
```

Expected modes are `0700` for the raw collector, analyzer, and sanitizer; `0755` for the report endpoint; and `0440` for sudoers. Only the report endpoint appears in `sudo -l`.

Inspect `/var/log/sudo-ai-auditor.log` if the platform's sudo build honors the configured logfile. Centralized or tamper-resistant log export is not currently provided.

## Rollback

The sudoers script keeps timestamped backups of an existing rule. Restore a reviewed backup with `install -o root -g root -m 0440`, validate it with `visudo`, and atomically rename it into place. Removing the service account or active sudoers file is destructive and should be done explicitly by an administrator.
