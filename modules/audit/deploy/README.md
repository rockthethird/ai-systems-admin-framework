# Deploy the AI auditor

Run deployment against a snapshot-backed or disposable Linux target. The scripts assume the repository is present on that target unless noted otherwise.

## Sequence

Review the four YAML files under `policy/` before generating artifacts.
Generated files under `artifacts/` are local deployment inputs and must not
be edited by hand.

```bash
# Target: create locked cloud and local report identities (no SSH keys)
sudo bash modules/audit/deploy/scripts/create-report-identities.sh

# Target: install root-only audit helpers and the sanitized endpoint
sudo bash modules/audit/deploy/scripts/install-report-runtime.sh

# Controller: build and validate the manifest and sudoers artifacts
python3 modules/audit/deploy/scripts/policy.py build

# Controller: inspect exact artifact bytes and approve their bundle digest
python3 modules/audit/deploy/scripts/policy.py review

# Controller: independently reconstruct and verify the approved bundle
python3 modules/audit/deploy/scripts/policy.py verify

# Target: validate a root-owned candidate and activate it atomically
sudo bash modules/audit/deploy/scripts/install-sudoers.sh
```

Stop here before configuring SSH. The existing key and SSH-hardening scripts target the legacy `ai-auditor` identity and must not be applied to the two report identities until profile-specific key and forced-command binding is designed.

The sudoers deployment requires `visudo`; skipping validation is not an acceptable production path.

Sudoers is rendered directly from the validated identity policy. Fixed
renderer invariants enforce root-only, no-argument endpoints and hardened
environment defaults; `visudo` must accept the candidate before publication.
Review requires an interactive terminal and the policy-directory owner. It
prints each exact artifact with its destination, ownership, mode, and hash,
then records approval only when the full bundle digest is entered correctly.
Approval state is local under `.state/` and is never a deployment artifact.

## Verify

```bash
sudo -u ai-auditor-cloud sudo -n /usr/local/libexec/ai-auditor-report > /tmp/external-findings.json
sudo -u ai-auditor-local sudo -n /usr/local/libexec/ai-auditor-report-internal > /tmp/internal-findings.json
python3 -m json.tool /tmp/external-findings.json >/dev/null

# These must fail.
sudo -u ai-auditor-cloud sudo -n /usr/local/libexec/ai-auditor-report-internal
sudo -u ai-auditor-local sudo -n /usr/local/libexec/ai-auditor-report
sudo -u ai-auditor-cloud sudo -n /usr/local/libexec/ai-auditor-inventory
sudo -u ai-auditor-local sudo -n /bin/sh -c id

sudo visudo -c -f /etc/sudoers.d/ai-auditor
sudo stat -c '%U:%G %a %n' /usr/local/libexec/ai-auditor-{inventory,analyze-inventory,sanitize-findings,report} /etc/sudoers.d/ai-auditor
sudo -l -U ai-auditor-cloud
sudo -l -U ai-auditor-local
```

Expected modes are `0700` for the raw collector, analyzer, and sanitizers; `0755` for both report endpoints; and `0440` for sudoers. Each identity sees only its assigned endpoint in `sudo -l`. SSH key binding is a separate, intentionally deferred step.

Inspect `/var/log/sudo-ai-auditor-cloud.log` and
`/var/log/sudo-ai-auditor-local.log` if the platform's sudo build honors the
configured logfiles. Centralized or tamper-resistant log export is not
currently provided.

## Rollback

The sudoers script keeps timestamped backups of an existing rule. Restore a reviewed backup with `install -o root -g root -m 0440`, validate it with `visudo`, and atomically rename it into place. Removing the service account or active sudoers file is destructive and should be done explicitly by an administrator.
