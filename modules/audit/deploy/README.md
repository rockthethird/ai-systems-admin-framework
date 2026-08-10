# Deploy the AI auditor

Run deployment against a snapshot-backed or disposable Linux target. The scripts assume the repository is present on that target unless noted otherwise.

## Sequence

```bash
# Target: create the service account
sudo bash modules/audit/deploy/10-create-user.sh

# Target: install and smoke-test the fixed collector atomically
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
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-inventory > /tmp/inventory.json
python3 -m json.tool /tmp/inventory.json >/dev/null

# These must fail.
sudo -u ai-auditor sudo -n /usr/local/libexec/ai-auditor-inventory unexpected
sudo -u ai-auditor sudo -n /bin/sh -c id

sudo visudo -c -f /etc/sudoers.d/ai-auditor
sudo stat -c '%U:%G %a %n' /usr/local/libexec/ai-auditor-inventory /etc/sudoers.d/ai-auditor
sudo -l -U ai-auditor
```

Inspect `/var/log/sudo-ai-auditor.log` if the platform's sudo build honors the configured logfile. Centralized or tamper-resistant log export is not currently provided.

## Rollback

The sudoers script keeps timestamped backups of an existing rule. Restore a reviewed backup with `install -o root -g root -m 0440`, validate it with `visudo`, and atomically rename it into place. Removing the service account or active sudoers file is destructive and should be done explicitly by an administrator.
