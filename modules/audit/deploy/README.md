# Deploy the AI auditor

Run deployment against a snapshot-backed or disposable Linux target. The scripts assume the repository is present on that target unless noted otherwise.

## Sequence

Review the five YAML files under `policy/` before generating artifacts.
Generated files under `artifacts/` are local deployment inputs and must not
be edited by hand.

```bash
# Controller: build and validate the manifest and sudoers artifacts
python3 modules/audit/deploy/scripts/policy.py build

# Controller: inspect local artifacts and approve their bundle digest
python3 modules/audit/deploy/scripts/policy.py review

# Controller: independently reconstruct and verify the approved bundle
python3 modules/audit/deploy/scripts/policy.py verify

# Target: run the complete read-only preflight
sudo modules/audit/deploy/scripts/deploy.sh --check

# Target: repeat preflight, confirm, and deploy all stages
sudo modules/audit/deploy/scripts/deploy.sh
```

The public deployment interface is `scripts/deploy.sh`. Non-executable stage
libraries under `scripts/lib/` implement identity, runtime, and sudoers work;
they are not independent operator entry points. Preflight completes before any
permanent change. The complete application tree is staged from the approved
`artifacts/rootfs/`, verified again, and atomically activated under
`/opt/ai-auditor`. Sudoers is activated only after the application succeeds.

An interactive deployment warns on a dirty Git checkout and defaults to abort;
the administrator may explicitly answer `y` or `yes` to test the patch.
`--check` and noninteractive deployment require `--allow-dirty`. Source without
usable Git metadata always requires `--allow-unversioned`. Automation must
additionally provide both `--non-interactive` and `--approved-sha256 DIGEST`;
this bypasses only the final confirmation.

Stop here before configuring SSH. Profile-specific key and forced-command
binding is not implemented; its required security properties are defined in
[`../docs/THREAT-MODEL.md`](../docs/THREAT-MODEL.md).

The sudoers deployment requires `visudo`; skipping validation is not an acceptable production path.

Sudoers is rendered directly from the validated identity policy. Fixed
renderer invariants enforce root-only, no-argument endpoints and hardened
environment defaults; `visudo` must accept the candidate before publication.
Review requires the policy-directory owner and an interactive terminal with
alternate-screen support and at least 80 columns by 24 lines. Its six-stage
wizard separates automated validation, policy and schema review, runtime source
review, generated output review, installation-plan review, and final approval.
Each stage replaces the previous display; the original terminal screen returns
when review exits.

Enter, Space, `n`, Vim motion keys, and forward arrow keys advance immediately.
`b`, `p`, Vim motion keys, and back arrow keys return to earlier stages. `q`,
Escape, Ctrl-C, Ctrl-D, or end-of-input abort from navigation without recording
a new approval. A forward action at the final stage opens normal line input for
the complete approval digest; there, Ctrl-C returns to final-stage navigation
and Ctrl-D aborts. Stage navigation is informational, is not retained, and does
not imply that a human completed the review.

The exact policy, runtime sources, and artifact tree are checked when review
starts, immediately before the final digest prompt, and again after the digest
is entered. If a reviewed path is added, removed, or modified while the wizard
is open, review aborts, identifies the affected relative paths, and requires a
restart. The wizard never rebuilds in response to such a change. File hashes
remain available for optional independent verification. Approval is recorded
only when the complete artifact-index digest is entered correctly and the final
integrity check passes. Approval state is local under `.state/` and is never a
deployment artifact.

## Verify

```bash
sudo -u ai-auditor-cloud sudo -n /opt/ai-auditor/bin/report-external > /tmp/external-findings.json
sudo -u ai-auditor-local sudo -n /opt/ai-auditor/bin/report-internal > /tmp/internal-findings.json
python3 -m json.tool /tmp/external-findings.json >/dev/null

# These must fail.
sudo -u ai-auditor-cloud sudo -n /opt/ai-auditor/bin/report-internal
sudo -u ai-auditor-local sudo -n /opt/ai-auditor/bin/report-external
sudo -u ai-auditor-cloud sudo -n /opt/ai-auditor/lib/collect.py
sudo -u ai-auditor-local sudo -n /bin/sh -c id

sudo visudo -c -f /etc/sudoers.d/ai-auditor
sudo find /opt/ai-auditor -printf '%u:%g %m %p\n'
sudo stat -c '%U:%G %a %n' /etc/sudoers.d/ai-auditor
sudo -l -U ai-auditor-cloud
sudo -l -U ai-auditor-local
```

Expected modes are `0700` for the raw collector, analyzer, and sanitizers; `0755` for both report endpoints; and `0440` for sudoers. Each identity sees only its assigned endpoint in `sudo -l`. SSH key binding is a separate, intentionally deferred step.

Inspect `/var/log/sudo-ai-auditor-cloud.log` and
`/var/log/sudo-ai-auditor-local.log` if the platform's sudo build honors the
configured logfiles. Centralized or tamper-resistant log export is not
currently provided.

## Rollback

Deployment retains the previous application tree only until the new tree and
sudoers rule activate successfully; failures during that transaction restore
the previous tree. Longer-term rollback requires rebuilding and approving the
desired Git revision. Removing an identity or active sudoers file remains an
explicit administrator action.
